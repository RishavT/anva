"""Chromium evidence for the browser-native Organizational Canvas."""

from __future__ import annotations

import json
import math
import os
import platform
import uuid
from datetime import timedelta
from pathlib import Path
from shutil import which
from typing import cast

import pytest
from django.utils import timezone
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import Select, WebDriverWait

from anva.core.models import (
    AccessScope,
    AssertionConflict,
    CanvasAnnotation,
    CanvasView,
    KnowledgeAssertion,
    KnowledgeEntity,
    KnowledgeProposal,
    KnowledgeRelationship,
    Membership,
    Repository,
    User,
)
from anva.core.services.canvas import create_canvas_view
from anva.core.services.context import ActorContext
from anva.core.services.ingestion import (
    connect_filesystem_source,
    execute_ingestion_job,
    request_ingestion_sync,
)
from anva.core.services.jobs import claim_next_job, complete_job

SCREENSHOTS = Path("docs/evidence/issue-012/screenshots")
PERFORMANCE_ROOT = Path("docs/evidence/issue-012/performance")


def _metric_summary(samples: list[float]) -> dict[str, object]:
    ordered = sorted(samples)
    percentile_95 = ordered[math.ceil(len(ordered) * 0.95) - 1]
    middle = len(ordered) // 2
    percentile_50 = (ordered[middle - 1] + ordered[middle]) / 2
    return {
        "raw": [round(value, 3) for value in samples],
        "p50": round(percentile_50, 3),
        "p95": round(percentile_95, 3),
        "max": round(max(samples), 3),
        "sample_count": len(samples),
    }


def _cpu_model() -> str:
    for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("model name"):
            return line.partition(":")[2].strip()
    return "unavailable"


def _capture(driver: webdriver.Chrome, name: str) -> None:
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    state = driver.execute_async_script(
        """
        const done = arguments[0];
        const preservedTop = window.scrollY;
        if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
        requestAnimationFrame(() => {
          const scroller = document.scrollingElement;
          window.scrollTo({ left: 0, top: preservedTop, behavior: "instant" });
          scroller.scrollLeft = 0;
          document.documentElement.scrollLeft = 0;
          document.body.scrollLeft = 0;
          for (const element of document.querySelectorAll("*")) element.scrollLeft = 0;
          requestAnimationFrame(() => requestAnimationFrame(() => {
            const sidebar = document.getElementById("primary-navigation");
            const desktop = window.innerWidth > 896;
            const sidebarBounds = sidebar?.getBoundingClientRect();
            done({
              windowScrollX: window.scrollX,
              visualViewportPageLeft: window.visualViewport?.pageLeft || 0,
              documentScrollLeft: document.documentElement.scrollLeft,
              bodyScrollLeft: document.body.scrollLeft,
              descendantScrollers: [...document.querySelectorAll("*")]
                .filter((element) => element.scrollLeft !== 0)
                .map((element) => element.tagName),
              desktopSidebarLeft: desktop ? sidebarBounds?.left : null,
              desktopSidebarVisible: desktop
                ? Boolean(sidebar && sidebar.open && sidebarBounds?.width)
                : null,
            });
          }));
        });
        """
    )
    assert state == {
        "windowScrollX": 0,
        "visualViewportPageLeft": 0,
        "documentScrollLeft": 0,
        "bodyScrollLeft": 0,
        "descendantScrollers": [],
        "desktopSidebarLeft": 0 if driver.get_window_size()["width"] > 896 else None,
        "desktopSidebarVisible": True if driver.get_window_size()["width"] > 896 else None,
    }
    driver.save_screenshot(str(SCREENSHOTS / name))


def _chrome() -> webdriver.Chrome:
    options = Options()
    options.binary_location = "/usr/bin/chromium"
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-breakpad")
    options.add_argument("--disable-crash-reporter")
    options.add_argument("--window-size=1440,1024")
    options.add_argument("--force-device-scale-factor=1")
    options.add_argument(f"--user-data-dir=/tmp/anva-canvas-chrome-{uuid.uuid4()}")
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    return webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)


def _setup(driver: webdriver.Chrome, base_url: str) -> None:
    driver.get(f"{base_url}/setup")
    values = {
        "organization_name": "Northstar Systems",
        "organization_slug": "northstar",
        "admin_name": "Ada Morgan",
        "admin_email": "admin@northstar.test",
        "repository_name": "payments",
        "repository_external_id": "github:northstar/payments",
        "bootstrap_secret": "test-only-bootstrap-secret",
    }
    for name, value in values.items():
        driver.find_element(By.NAME, name).send_keys(value)
    driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()


def _seed_canvas(root: Path) -> tuple[CanvasView, dict[str, KnowledgeEntity]]:
    repository = Repository.objects.get(external_id="github:northstar/payments")
    organization = repository.organization
    scope = AccessScope.objects.get(organization=organization, is_active=True)
    user = User.objects.get(email="admin@northstar.test")
    Membership.objects.get(organization=organization, user=user)
    entities: dict[str, KnowledgeEntity] = {}
    for key, entity_type, canonical_key, display_name, owner, status, risk in (
        (
            "goal",
            "GOAL",
            "goal:retention",
            "Increase customer retention",
            "Growth",
            "ACTIVE",
            "LOW",
        ),
        ("metric", "METRIC", "metric:nrr", "Net revenue retention", "Finance", "TRACKED", "LOW"),
        (
            "initiative",
            "INITIATIVE",
            "initiative:checkout",
            "Checkout modernization",
            "Commerce",
            "ACTIVE",
            "MEDIUM",
        ),
        (
            "requirement",
            "REQUIREMENT",
            "requirement:checkout-slo",
            "Checkout availability requirement",
            "Commerce",
            "ACTIVE",
            "MEDIUM",
        ),
        (
            "pull_request",
            "PULL_REQUEST",
            "pull-request:482",
            "PR #482 resilient checkout",
            "Platform",
            "OPEN",
            "LOW",
        ),
        ("product", "PRODUCT", "product:storefront", "Storefront", "Commerce", "ACTIVE", "MEDIUM"),
        (
            "component",
            "COMPONENT",
            "component:checkout",
            "Checkout component",
            "Commerce",
            "ACTIVE",
            "MEDIUM",
        ),
        ("api", "API", "api:payments", "Payments API", "Platform", "ACTIVE", "HIGH"),
        (
            "repository",
            "REPOSITORY",
            "repository:payments",
            "Payments repository",
            "Platform",
            "ACTIVE",
            "LOW",
        ),
        ("service", "SERVICE", "service:payments", "Payments خدمة", "Platform", "HEALTHY", "HIGH"),
        ("team", "TEAM", "team:platform", "Platform team", "Engineering", "ACTIVE", "LOW"),
        (
            "risk",
            "RISK",
            "risk:provider",
            "External provider concentration",
            "Risk",
            "OPEN",
            "HIGH",
        ),
        ("policy", "POLICY", "policy:pci", "PCI change policy", "Security", "ACTIVE", "MEDIUM"),
        (
            "incident",
            "INCIDENT",
            "incident:payments",
            "Payments provider incident",
            "SRE",
            "RESOLVED",
            "HIGH",
        ),
        (
            "decision",
            "DECISION",
            "decision:retry",
            "Adopt idempotent payment retries",
            "Architecture",
            "ACCEPTED",
            "LOW",
        ),
        (
            "task",
            "TASK",
            "task:checkout",
            "Implement checkout retries",
            "Platform",
            "IN_PROGRESS",
            "MEDIUM",
        ),
    ):
        entities[key] = KnowledgeEntity.objects.create(
            organization=organization,
            access_scope=scope,
            entity_type=entity_type,
            canonical_key=canonical_key,
            display_name=display_name,
            attributes={"owner": owner, "status": status, "risk": risk},
        )
    actor = ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="browser:canvas",
        request_id=uuid.uuid4(),
    )
    root.mkdir()
    (root / "service.json").write_text(
        json.dumps(
            {
                "service": "billing-runtime",
                "owner": "platform",
                "system": "checkout",
                "repository": "payments",
                "status": "active",
            }
        ),
        encoding="utf-8",
    )
    source, created = connect_filesystem_source(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        external_key="filesystem:browser-canvas-source",
        display_name="Browser Canvas source",
        root=str(root),
    )
    assert created
    _run, created = request_ingestion_sync(actor=actor, source_connection_id=source.id)
    assert created
    worker_id = "browser-canvas-worker"
    job = claim_next_job(worker_id=worker_id, lease_seconds=600)
    assert job is not None
    completed = execute_ingestion_job(job=job, worker_id=worker_id)
    complete_job(
        actor=ActorContext(
            organization_id=organization.id,
            actor_type="SERVICE",
            actor_id=worker_id,
            authorization_path="internal:browser-worker",
            request_id=uuid.uuid4(),
        ),
        job_id=job.id,
        worker_id=worker_id,
    )
    assert completed.state in {completed.State.COMPLETED, completed.State.PARTIALLY_COMPLETED}
    seed = KnowledgeRelationship.objects.filter(organization=organization).first()
    assert seed is not None

    def assertion_for(
        entity: KnowledgeEntity,
        predicate: str,
        *,
        inferred: bool = False,
        freshness: str = KnowledgeAssertion.StalenessState.FRESH,
    ) -> KnowledgeAssertion:
        observed_at = timezone.now() - (
            timedelta(days=180)
            if freshness == KnowledgeAssertion.StalenessState.STALE
            else timedelta()
        )
        return KnowledgeAssertion.objects.create(
            organization=organization,
            subject_key=entity.canonical_key,
            predicate=predicate,
            value={"fixture": "authorized-ingestion-derived"},
            is_inferred=inferred,
            extraction_class=seed.assertion.extraction_class,
            extraction_method="browser-fixture-from-ingestion",
            confidence=0.82 if inferred else 0.97,
            valid_from=observed_at,
            observed_at=observed_at,
            staleness_state=freshness,
            provenance=seed.assertion.provenance,
            review_state=KnowledgeAssertion.ReviewState.AUTO_ACCEPTED,
            access_scope=scope,
        )

    def relationship(
        relationship_type: str,
        source_entity: KnowledgeEntity,
        target_entity: KnowledgeEntity,
        *,
        assertion: KnowledgeAssertion | None = None,
    ) -> KnowledgeRelationship:
        basis = assertion or seed.assertion
        return KnowledgeRelationship.objects.create(
            organization=organization,
            relationship_type=relationship_type,
            source_entity=source_entity,
            target_entity=target_entity,
            source_entity_type=source_entity.entity_type,
            target_entity_type=target_entity.entity_type,
            assertion=basis,
            source_location=seed.source_location,
            source_observation=seed.source_observation,
            access_snapshot=seed.access_snapshot,
            access_scope=scope,
            extraction_class=basis.extraction_class,
            confidence=basis.confidence,
            observed_at=basis.observed_at,
            review_state=KnowledgeRelationship.ReviewState.CONFIRMED,
        )

    for relationship_type, source_key, target_key in (
        ("GOAL_MEASURED_BY_METRIC", "goal", "metric"),
        ("INITIATIVE_SUPPORTS_GOAL", "initiative", "goal"),
        ("REQUIREMENT_SUPPORTS_INITIATIVE", "requirement", "initiative"),
        ("REQUIREMENT_IMPLEMENTED_BY_PULL_REQUEST", "requirement", "pull_request"),
        ("INITIATIVE_AFFECTS_PRODUCT", "initiative", "product"),
        ("PRODUCT_IMPLEMENTED_BY_REPOSITORY", "product", "repository"),
        ("COMPONENT_BELONGS_TO_PRODUCT", "component", "product"),
        ("API_CONSUMED_BY_COMPONENT", "api", "component"),
        ("API_PROVIDED_BY_SERVICE", "api", "service"),
        ("SERVICE_IMPLEMENTED_BY_REPOSITORY", "service", "repository"),
        ("REPOSITORY_OWNED_BY_TEAM", "repository", "team"),
        ("RISK_AFFECTS_ENTITY", "risk", "product"),
        ("POLICY_APPLIES_TO_ENTITY", "policy", "service"),
        ("INCIDENT_AFFECTED_ENTITY", "incident", "service"),
        ("DECISION_APPLIES_TO_ENTITY", "decision", "service"),
        ("TASK_CHANGES_ENTITY", "task", "product"),
        ("PULL_REQUEST_CHANGES_ENTITY", "pull_request", "product"),
    ):
        relationship(relationship_type, entities[source_key], entities[target_key])

    dense_services = [
        KnowledgeEntity.objects.create(
            organization=organization,
            access_scope=scope,
            entity_type=KnowledgeEntity.EntityType.SERVICE,
            canonical_key=f"service:dense:{index:02d}",
            display_name=f"Dense dependency service {index:02d}",
            attributes={"owner": "Platform", "status": "ACTIVE", "risk": "MEDIUM"},
        )
        for index in range(36)
    ]
    for index, dense_service in enumerate(dense_services):
        relationship("SERVICE_DEPENDS_ON_SERVICE", entities["service"], dense_service)
        relationship(
            "SERVICE_DEPENDS_ON_SERVICE",
            dense_service,
            dense_services[(index + 1) % len(dense_services)],
        )
        relationship(
            "SERVICE_DEPENDS_ON_SERVICE",
            dense_service,
            dense_services[(index + 5) % len(dense_services)],
        )
    relationship(
        "DEPENDS_ON",
        entities["service"],
        dense_services[0],
    )
    for index in range(20):
        component = KnowledgeEntity.objects.create(
            organization=organization,
            access_scope=scope,
            entity_type=KnowledgeEntity.EntityType.COMPONENT,
            canonical_key=f"component:dense:{index:02d}",
            display_name=f"Dense checkout component {index:02d}",
            attributes={"owner": "Commerce", "status": "ACTIVE", "risk": "LOW"},
        )
        relationship("COMPONENT_BELONGS_TO_PRODUCT", component, entities["product"])
        relationship("REPOSITORY_CONTAINS_COMPONENT", entities["repository"], component)

    stale_assertion = assertion_for(
        dense_services[0],
        "stale owner",
        freshness=KnowledgeAssertion.StalenessState.STALE,
    )
    inferred_assertion = assertion_for(
        dense_services[1],
        "inferred dependency",
        inferred=True,
    )
    conflict_left = assertion_for(dense_services[2], "runtime owner")
    conflict_right = assertion_for(
        dense_services[2],
        "runtime owner candidate",
        freshness=KnowledgeAssertion.StalenessState.CONTRADICTED,
    )
    AssertionConflict.objects.create(
        organization=organization,
        left_assertion=conflict_left,
        right_assertion=conflict_right,
        predicate="owner",
    )
    assert stale_assertion.staleness_state == KnowledgeAssertion.StalenessState.STALE
    assert inferred_assertion.is_inferred is True

    foreign = Repository.objects.create(
        organization=organization,
        external_id="github:northstar/hidden",
        name="hidden",
        is_active=False,
    )
    assert foreign.is_active is False
    hidden_scope = AccessScope.objects.create(
        organization=organization,
        name="inactive hidden scope",
        all_repositories=False,
        is_active=False,
    )
    KnowledgeEntity.objects.create(
        organization=organization,
        access_scope=hidden_scope,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:CANARY-HIDDEN-DENSE",
        display_name="CANARY-HIDDEN-DENSE",
    )
    view, created = create_canvas_view(
        actor=actor,
        name="Storefront operating map",
        description="Strategy through systems, ownership, and risk.",
        view_type=CanvasView.ViewType.CUSTOM,
        semantic_query={"repository_ids": [str(repository.id)]},
        repository_id=repository.id,
        access_scope_id=None,
        idempotency_key="browser-storefront-map",
    )
    assert created
    return view, entities


def _add_performance_nodes() -> None:
    user = User.objects.get(email="admin@northstar.test")
    organization = Membership.objects.get(user=user).organization
    scope = AccessScope.objects.get(organization=organization, is_active=True)
    remaining = (
        300
        - KnowledgeEntity.objects.filter(
            organization=organization,
            access_scope=scope,
        ).count()
    )
    assert remaining > 0
    KnowledgeEntity.objects.bulk_create(
        [
            KnowledgeEntity(
                organization=organization,
                access_scope=scope,
                entity_type=KnowledgeEntity.EntityType.COMPONENT,
                canonical_key=f"component:browser-performance:{index:03d}",
                display_name=f"Performance component {index:03d}",
                attributes={"owner": "Performance", "status": "ACTIVE", "risk": "LOW"},
            )
            for index in range(remaining)
        ]
    )
    assert (
        KnowledgeEntity.objects.filter(organization=organization, access_scope=scope).count() == 300
    )


@pytest.mark.browser
@pytest.mark.skipif(which("chromedriver") is None, reason="Chromium test stage is required")
@pytest.mark.django_db(transaction=True)
def test_organizational_canvas_interaction_no_js_and_responsive_evidence(
    live_server: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(tmp_path))
    base_url = str(live_server)
    driver = _chrome()
    wait = WebDriverWait(driver, 12)
    try:
        _setup(driver, base_url)
        wait.until(expected_conditions.url_contains("/app/onboarding"))
        view, entities = _seed_canvas(tmp_path / "browser-source")
        product = entities["product"]
        repository_entity = entities["repository"]

        driver.get(f"{base_url}/app/canvas?view={view.id}")
        wait.until(lambda current: len(current.find_elements(By.CSS_SELECTOR, ".canvas-node")) >= 8)
        assert driver.find_element(By.TAG_NAME, "h1").text == "Organizational Canvas"
        assert driver.execute_script("return Boolean(window.dagre?.graphlib)")
        assert driver.find_element(By.CSS_SELECTOR, "[data-canvas-minimap]").is_displayed()
        assert driver.execute_script(
            "return JSON.parse(document.getElementById('canvas-data').textContent).edges.length > 0"
        )
        graph_shape = driver.execute_script(
            "const graph = JSON.parse(document.getElementById('canvas-data').textContent);"
            "const degree = new Map(graph.nodes.map((node) => [node.id, 0]));"
            "const pairs = new Map();"
            "for (const edge of graph.edges) {"
            " degree.set(edge.source, (degree.get(edge.source) || 0) + 1);"
            " degree.set(edge.target, (degree.get(edge.target) || 0) + 1);"
            " const pair = `${edge.source}:${edge.target}`;"
            " pairs.set(pair, (pairs.get(pair) || 0) + 1);"
            "}"
            "const adjacency = new Map(graph.nodes.map((node) => [node.id, []]));"
            "graph.edges.forEach((edge) => adjacency.get(edge.source)?.push(edge.target));"
            "const visiting = new Set(), visited = new Set();"
            "const cyclic = (id) => {"
            " if (visiting.has(id)) return true;"
            " if (visited.has(id)) return false;"
            " visiting.add(id);"
            " for (const next of adjacency.get(id) || []) if (cyclic(next)) return true;"
            " visiting.delete(id); visited.add(id); return false;"
            "};"
            "return {"
            " nodes: graph.nodes.length, edges: graph.edges.length,"
            " maxDegree: Math.max(...degree.values()),"
            " parallel: Math.max(...pairs.values()),"
            " cycle: graph.nodes.some((node) => cyclic(node.id)),"
            " stale: graph.nodes.some((node) => node.freshness === 'STALE'),"
            " inferred: graph.nodes.some((node) => node.is_inferred),"
            " conflict: graph.nodes.some((node) => node.has_conflict),"
            " hiddenLeak: document.getElementById('canvas-data').textContent"
            ".includes('CANARY-HIDDEN')"
            "};"
        )
        assert graph_shape["nodes"] >= 70
        assert graph_shape["edges"] >= 160
        assert graph_shape["maxDegree"] >= 35
        assert graph_shape["parallel"] >= 2
        assert graph_shape["cycle"] is True
        assert graph_shape["stale"] is True
        assert graph_shape["inferred"] is True
        assert graph_shape["conflict"] is True
        assert graph_shape["hiddenLeak"] is False
        assert "Payments خدمة" in driver.find_element(By.TAG_NAME, "main").text
        assert (
            len(
                driver.find_elements(
                    By.CSS_SELECTOR, ".canvas-proposal select[name='relationship_type'] option"
                )
            )
            == 24
        )
        _capture(driver, "01-canvas-desktop.png")

        for source, target in (
            (entities["goal"], entities["pull_request"]),
            (entities["product"], entities["team"]),
        ):
            path_form = driver.find_element(By.CSS_SELECTOR, ".canvas-path-form")
            Select(path_form.find_element(By.NAME, "path_from")).select_by_value(str(source.id))
            Select(path_form.find_element(By.NAME, "path_to")).select_by_value(str(target.id))
            path_form.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
            wait.until(
                expected_conditions.presence_of_element_located(
                    (By.CSS_SELECTOR, ".canvas-path-result ol")
                )
            )
            assert len(driver.find_elements(By.CSS_SELECTOR, ".canvas-path-result li")) >= 2
        path_result = driver.find_element(By.CSS_SELECTOR, ".canvas-path-result")
        driver.execute_script(
            "arguments[0].scrollIntoView({block: 'center', inline: 'nearest'})", path_result
        )
        _capture(driver, "06-canvas-required-traces.png")
        driver.get(f"{base_url}/app/canvas?view={view.id}")
        wait.until(
            lambda current: len(current.find_elements(By.CSS_SELECTOR, ".canvas-node")) >= 70
        )

        first_node = driver.find_element(By.CSS_SELECTOR, ".canvas-node")
        first_node.click()
        wait.until(
            lambda current: current.find_element(By.ID, "canvas-inspector-title").text
            != "Select a node"
        )
        question_form = driver.find_element(By.CSS_SELECTOR, "[data-canvas-question]")
        question_form.find_element(By.NAME, "q").send_keys("billing-runtime")
        question_form.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
        wait.until(
            lambda current: "billing-runtime"
            in current.find_element(By.CSS_SELECTOR, "[data-canvas-question-results]").text
        )
        driver.find_element(By.CSS_SELECTOR, "[data-canvas-annotation-body]").send_keys(
            "Review this dependency before the next release."
        )
        driver.find_element(By.CSS_SELECTOR, "[data-canvas-add-annotation]").click()
        assert (
            "Review this dependency"
            in driver.find_element(By.CSS_SELECTOR, "[data-canvas-annotations]").text
        )
        driver.find_element(By.CSS_SELECTOR, "[data-canvas-zoom-in]").click()
        assert driver.find_element(By.CSS_SELECTOR, "[data-canvas-zoom]").text != "100%"
        ActionChains(driver).click_and_hold(first_node).move_by_offset(48, 30).release().perform()
        driver.find_element(By.CSS_SELECTOR, "[data-canvas-save]").click()
        wait.until(
            expected_conditions.text_to_be_present_in_element(
                (By.CSS_SELECTOR, "[data-canvas-save]"), "Saved r2"
            )
        )
        view.refresh_from_db()
        assert view.revision == 2
        assert CanvasAnnotation.objects.filter(view_revision__canvas_view=view).count() == 1
        _capture(driver, "02-canvas-inspector-saved-layout.png")

        driver.find_element(By.CSS_SELECTOR, "[data-canvas-draw-relationship]").click()
        Select(driver.find_element(By.CSS_SELECTOR, "[data-canvas-proposal-type]")).select_by_value(
            "PRODUCT_IMPLEMENTED_BY_REPOSITORY"
        )
        proposal_source = driver.find_element(
            By.CSS_SELECTOR, f'.canvas-node[data-node-id="{product.id}"]'
        )
        proposal_target = driver.find_element(
            By.CSS_SELECTOR, f'.canvas-node[data-node-id="{repository_entity.id}"]'
        )
        ActionChains(driver).click_and_hold(proposal_source).move_to_element(
            proposal_target
        ).release().perform()
        wait.until(
            lambda current: not current.find_element(
                By.CSS_SELECTOR, "[data-canvas-submit-proposal]"
            ).get_attribute("disabled")
        )
        assert driver.find_element(By.CSS_SELECTOR, "[data-canvas-proposal-edge]").is_displayed()
        driver.find_element(By.CSS_SELECTOR, "[data-canvas-submit-proposal]").click()
        proposal = driver.find_element(By.CSS_SELECTOR, ".canvas-proposal")
        assert proposal.get_attribute("open") is not None
        assert Select(
            proposal.find_element(By.NAME, "source_id")
        ).first_selected_option.get_attribute("value") == str(product.id)
        assert Select(
            proposal.find_element(By.NAME, "target_id")
        ).first_selected_option.get_attribute("value") == str(repository_entity.id)
        proposal.find_element(By.NAME, "rationale").send_keys(
            "The governed Storefront product is implemented in this repository."
        )
        relationship_count = KnowledgeRelationship.objects.count()
        proposal.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
        wait.until(expected_conditions.url_contains("notice=Relationship+proposal"))
        assert KnowledgeProposal.objects.count() == 1
        assert KnowledgeRelationship.objects.count() == relationship_count

        _add_performance_nodes()
        driver.set_window_size(1440, 1024)
        performance_url = f"{base_url}/app/canvas?view={view.id}"
        shell_ms: list[float] = []
        layout_ms: list[float] = []
        payload_bytes_samples: list[float] = []
        external_request_samples: list[float] = []
        resource_origins: set[str] = set()
        for sample in range(31):
            driver.get(performance_url)
            wait.until(
                lambda current: current.find_element(By.TAG_NAME, "html").get_attribute(
                    "data-canvas-interactive"
                )
                == "true"
            )
            assert len(driver.find_elements(By.CSS_SELECTOR, ".canvas-node")) == 300
            metrics = driver.execute_script(
                "const origin = window.location.origin;"
                "const resources = performance.getEntriesByType('resource');"
                "return {"
                "shell: performance.getEntriesByName("
                "'anva-canvas-shell-interactive').at(-1).duration,"
                "layout: performance.getEntriesByName('anva-canvas-layout').at(-1).duration,"
                "payload: new TextEncoder().encode("
                "document.getElementById('canvas-data').textContent).length,"
                "external: resources.filter((item) => new URL(item.name).origin !== origin).length,"
                "origins: [...new Set(resources.map((item) => new URL(item.name).origin))]"
                "};"
            )
            resource_origins.update(metrics["origins"])
            if sample:
                shell_ms.append(float(metrics["shell"]))
                layout_ms.append(float(metrics["layout"]))
                payload_bytes_samples.append(float(metrics["payload"]))
                external_request_samples.append(float(metrics["external"]))

        driver.set_script_timeout(60)
        path_result = driver.execute_async_script(
            """
            const done = arguments[0];
            (async () => {
              const graph = JSON.parse(document.getElementById("canvas-data").textContent);
              const edge = graph.edges[0];
              const csrf = document.querySelector(
                "[data-canvas-csrf] input[name='csrfmiddlewaretoken']",
              ).value;
              const samples = [];
              for (let index = 0; index < 31; index += 1) {
                const started = performance.now();
                const response = await fetch("/app/canvas/path", {
                  method: "POST",
                  credentials: "same-origin",
                  headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
                  body: JSON.stringify({
                    source_id: edge.source,
                    target_id: edge.target,
                    repository_ids: graph.repositories.map((repository) => repository.id),
                    max_depth: 6,
                  }),
                });
                const payload = await response.json();
                if (!response.ok || !payload.found) throw new Error("path benchmark failed");
                if (index) samples.push(performance.now() - started);
              }
              done({ samples });
            })().catch((error) => done({ error: String(error) }));
            """
        )
        assert "error" not in path_result
        path_ms = [float(value) for value in path_result["samples"]]

        local_result = driver.execute_async_script(
            """
            const done = arguments[0];
            const pause = () => new Promise((resolve) => setTimeout(resolve, 0));
            (async () => {
              const search = document.querySelector(".canvas-filter-form input[name='q']");
              const freshness = document.querySelector(
                ".canvas-filter-form select[name='freshness']",
              );
              performance.clearMeasures("anva-canvas-filter-local");
              for (let index = 0; index < 31; index += 1) {
                search.value = index % 2 ? "Performance component" : "";
                search.dispatchEvent(new Event("input", { bubbles: true }));
                await pause();
              }
              const searchSamples = performance
                .getEntriesByName("anva-canvas-filter-local")
                .slice(1)
                .map((entry) => entry.duration);
              search.value = "";
              search.dispatchEvent(new Event("input", { bubbles: true }));
              await pause();

              performance.clearMeasures("anva-canvas-filter-local");
              for (let index = 0; index < 31; index += 1) {
                freshness.value = index % 2 ? "UNKNOWN" : "";
                freshness.dispatchEvent(new Event("change", { bubbles: true }));
                await pause();
              }
              const filterSamples = performance
                .getEntriesByName("anva-canvas-filter-local")
                .slice(1)
                .map((entry) => entry.duration);
              freshness.value = "";
              freshness.dispatchEvent(new Event("change", { bubbles: true }));
              await pause();

              performance.clearMeasures("anva-canvas-select-local");
              const nodes = [...document.querySelectorAll(".canvas-node")];
              for (let index = 0; index < 31; index += 1) {
                nodes[index % nodes.length].click();
                while (
                  document.querySelector("[data-inspector-summary]").textContent.includes("Loading")
                ) {
                  await new Promise((resolve) => setTimeout(resolve, 2));
                }
              }
              const selectSamples = performance
                .getEntriesByName("anva-canvas-select-local")
                .slice(1)
                .map((entry) => entry.duration);
              done({ searchSamples, filterSamples, selectSamples });
            })().catch((error) => done({ error: String(error) }));
            """
        )
        assert "error" not in local_result
        search_ms = [float(value) for value in local_result["searchSamples"]]
        filter_ms = [float(value) for value in local_result["filterSamples"]]
        select_ms = [float(value) for value in local_result["selectSamples"]]

        gesture_result = driver.execute_async_script(
            """
            const done = arguments[0];
            (async () => {
              const viewport = document.querySelector("[data-canvas-viewport]");
              await new Promise((resolve) => setTimeout(resolve, 50));
              window.__anvaCanvasLongTasks = [];
              performance.clearMeasures("anva-canvas-gesture-frame");
              performance.clearMeasures("anva-canvas-gesture-main-thread");
              for (let index = 0; index < 31; index += 1) {
                viewport.dispatchEvent(
                  new WheelEvent("wheel", {
                    deltaY: index % 2 ? 10 : -10,
                    clientX: 200,
                    clientY: 200,
                    bubbles: true,
                    cancelable: true,
                  }),
                );
                await new Promise((resolve) => requestAnimationFrame(resolve));
              }
              await new Promise((resolve) => setTimeout(resolve, 50));
              done({
                frameSamples: performance
                  .getEntriesByName("anva-canvas-gesture-frame")
                  .slice(1)
                  .map((entry) => entry.duration),
                workSamples: performance
                  .getEntriesByName("anva-canvas-gesture-main-thread")
                  .slice(1)
                  .map((entry) => entry.duration),
                longTasks: window.__anvaCanvasLongTasks || [],
                resourceOrigins: [
                  ...new Set(
                    performance
                      .getEntriesByType("resource")
                      .map((entry) => new URL(entry.name).origin),
                  ),
                ],
              });
            })().catch((error) => done({ error: String(error) }));
            """
        )
        assert "error" not in gesture_result
        gesture_frame_ms = [float(value) for value in gesture_result["frameSamples"]]
        gesture_work_ms = [float(value) for value in gesture_result["workSamples"]]
        long_tasks_ms = [float(value) for value in gesture_result["longTasks"]]
        resource_origins.update(gesture_result["resourceOrigins"])

        assert len(shell_ms) == len(layout_ms) == len(payload_bytes_samples) == 30
        assert len(path_ms) == len(search_ms) == len(filter_ms) == len(select_ms) == 30
        assert len(gesture_frame_ms) == len(gesture_work_ms) == 30
        summaries = {
            "shell_to_interactive_ms": _metric_summary(shell_ms),
            "dagre_layout_ms": _metric_summary(layout_ms),
            "path_http_round_trip_ms": _metric_summary(path_ms),
            "local_search_ms": _metric_summary(search_ms),
            "local_filter_ms": _metric_summary(filter_ms),
            "local_select_ms": _metric_summary(select_ms),
            "gesture_main_thread_work_ms": _metric_summary(gesture_work_ms),
            "gesture_event_to_animation_frame_ms": _metric_summary(gesture_frame_ms),
            "payload_bytes": _metric_summary(payload_bytes_samples),
            "external_request_count": _metric_summary(external_request_samples),
        }
        assert cast(float, summaries["shell_to_interactive_ms"]["p95"]) <= 2_000
        assert cast(float, summaries["dagre_layout_ms"]["p95"]) <= 250
        assert cast(float, summaries["path_http_round_trip_ms"]["p95"]) <= 1_000
        for metric in ("local_search_ms", "local_filter_ms", "local_select_ms"):
            assert cast(float, summaries[metric]["p95"]) <= 100
        assert cast(float, summaries["gesture_main_thread_work_ms"]["p95"]) <= 16.7
        assert max(payload_bytes_samples) <= 750 * 1024
        assert max(external_request_samples) == 0
        assert resource_origins == {base_url}
        assert long_tasks_ms == []

        capabilities = driver.capabilities
        browser_report = {
            "schema_version": "1",
            "metadata": {
                "commit": os.environ.get(
                    "ANVA_PERFORMANCE_COMMIT",
                    "fbb79960f96518a51cc8cf0e4f3ffb3090798378+working-tree",
                ),
                "environment": "Docker Compose browser-test profile, Chromium headless-new",
                "browser": capabilities["browserName"],
                "browser_version": capabilities["browserVersion"],
                "chromedriver_version": capabilities["chrome"]["chromedriverVersion"],
                "browser_image": os.environ.get(
                    "ANVA_PERFORMANCE_IMAGE",
                    "anva-i12-impl-browser-test@sha256:d840be65a8362767",
                ),
                "python": platform.python_version(),
                "platform": platform.platform(),
                "cpu_model": _cpu_model(),
                "cpu_count": os.cpu_count(),
                "viewport": {"width": 1440, "height": 1024, "device_scale_factor": 1},
                "fixture": {
                    "fixture_key": "canvas-browser-performance-v1",
                    "visible_nodes": 300,
                    "visible_relationships": graph_shape["edges"],
                    "repositories": 1,
                    "source": (
                        "real filesystem ingestion lineage plus authorized semantic trace and "
                        "dense dependency fixtures"
                    ),
                    "shape": {
                        "directed_cycle": True,
                        "maximum_degree": graph_shape["maxDegree"],
                        "parallel_edge_max": graph_shape["parallel"],
                        "stale_node": True,
                        "inferred_node": True,
                        "conflicted_node": True,
                        "hidden_canary_absent": True,
                    },
                },
            },
            "targets": {
                "shell_to_interactive_p95_ms": 2_000,
                "layout_p95_ms": 250,
                "path_p95_ms": 1_000,
                "local_interaction_p95_ms": 100,
                "gesture_main_thread_work_p95_ms": 16.7,
                "gesture_physical_frame_p95_ms": "not reliably measurable in headless mode",
                "long_task_max_ms": 50,
                "payload_bytes": 750 * 1024,
                "external_request_count": 0,
            },
            "metrics": {
                **summaries,
                "long_tasks_ms": long_tasks_ms,
                "long_task_count": len(long_tasks_ms),
                "resource_origins": sorted(resource_origins),
            },
            "notes": [
                "Every summary contains 30 samples after one discarded warm sample.",
                (
                    "Shell-to-interactive is Navigation Timing start through the production "
                    "Canvas script's final render, fit, and interactive marker."
                ),
                (
                    "Local search/filter/select timings are production Performance API "
                    "measures around synchronous authorized-DOM work; inspector network "
                    "fetch is intentionally excluded from local select."
                ),
                (
                    "Gesture main-thread work measures the production wheel handler and is "
                    "the enforceable 16.7 ms CPU budget. Event-to-requestAnimationFrame is "
                    "also recorded raw, but includes headless scheduler delay. Physical "
                    "display presentation/compositor timing is unavailable and is not claimed."
                ),
                (
                    "The Long Tasks API window is flushed and reset immediately before "
                    "the 31 gesture samples, and reports gesture-window main-thread tasks "
                    "at least 50 ms. It does not claim the whole benchmark session had no "
                    "Long Tasks. Resource Timing verifies every request remained same-origin."
                ),
            ],
        }
        PERFORMANCE_ROOT.mkdir(parents=True, exist_ok=True)
        (PERFORMANCE_ROOT / "browser.json").write_text(
            json.dumps(browser_report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _capture(driver, "05-canvas-300-node-performance.png")

        focus_form = driver.find_element(By.CSS_SELECTOR, ".canvas-filter-form")
        Select(focus_form.find_element(By.NAME, "focus")).select_by_value(
            str(entities["service"].id)
        )
        Select(focus_form.find_element(By.NAME, "depth")).select_by_value("1")
        focus_form.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
        wait.until(
            lambda current: current.find_element(By.TAG_NAME, "html").get_attribute(
                "data-canvas-interactive"
            )
            == "true"
        )
        focused_graph = driver.execute_script(
            "return JSON.parse(document.getElementById('canvas-data').textContent)"
        )
        assert focused_graph["semantic_query"]["root_entity_id"] == str(entities["service"].id)
        assert focused_graph["semantic_query"]["depth"] == 1
        assert 1 < focused_graph["counts"]["nodes"] < 100
        assert focused_graph["counts"]["edges"] < graph_shape["edges"]
        _capture(driver, "07-canvas-dense-progressive-focus.png")

        driver.execute_cdp_cmd("Emulation.setScriptExecutionDisabled", {"value": True})
        driver.set_window_size(320, 760)
        driver.get(f"{base_url}/app/canvas?view={view.id}")
        body_text = driver.find_element(By.TAG_NAME, "main").text
        assert "Permitted nodes" in body_text
        assert "Payments خدمة" in body_text
        assert driver.find_elements(By.CSS_SELECTOR, ".canvas-node") == []
        assert driver.execute_script(
            "return Math.max(document.documentElement.scrollWidth, document.body.scrollWidth)"
            " <= window.innerWidth"
        )
        navigation = driver.find_element(By.CSS_SELECTOR, "details[data-navigation]")
        if navigation.get_attribute("open") is not None:
            navigation.find_element(By.TAG_NAME, "summary").click()
        node_list = driver.find_element(By.ID, "canvas-node-list-title")
        driver.execute_script("arguments[0].scrollIntoView()", node_list)
        assert node_list.text == "Permitted nodes"
        _capture(driver, "03-canvas-mobile-320-no-js.png")

        driver.execute_cdp_cmd("Emulation.setScriptExecutionDisabled", {"value": False})
        driver.set_window_size(640, 760)
        driver.get(f"{base_url}/app/canvas?view={view.id}")
        for _step in range(5):
            ActionChains(driver).key_down(Keys.CONTROL).send_keys("+").key_up(
                Keys.CONTROL
            ).perform()
        assert driver.execute_script(
            "return Math.max(document.documentElement.scrollWidth, document.body.scrollWidth)"
            " <= window.innerWidth"
        )
        _capture(driver, "04-canvas-browser-zoom-200.png")

        severe_logs = [
            entry
            for entry in driver.get_log("browser")  # type: ignore[no-untyped-call]
            if entry.get("level") == "SEVERE"
            and "favicon.ico" not in str(entry.get("message", ""))
            and "404 (Not Found)" not in str(entry.get("message", ""))
        ]
        assert severe_logs == []
    finally:
        driver.quit()
