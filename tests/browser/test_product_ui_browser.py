"""Browser-native evidence for the primary server-rendered product journey."""

from __future__ import annotations

import uuid
from pathlib import Path
from shutil import which

import pytest
from django.utils import timezone
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import WebDriverWait

from anva.core.models import (
    AccessScope,
    AssuranceCheck,
    AssuranceRun,
    Finding,
    KnowledgeAssertion,
    KnowledgeEntity,
    PullRequest,
    Repository,
)

SCREENSHOTS = Path("docs/evidence/issue-011/remediation/screenshots")


def _capture(driver: webdriver.Chrome, name: str) -> None:
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
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
    options.add_argument(f"--user-data-dir=/tmp/anva-chrome-{uuid.uuid4()}")
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    return webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)


def _seed_product_records() -> tuple[Repository, KnowledgeEntity, KnowledgeAssertion, AssuranceRun]:
    repository = Repository.objects.get(external_id="github:northstar/payments")
    organization = repository.organization
    scope = AccessScope.objects.get(organization=organization)
    entity = KnowledgeEntity.objects.create(
        organization=organization,
        access_scope=scope,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:payments",
        display_name="Payments service",
        attributes={"tier": "critical"},
    )
    assertion = KnowledgeAssertion.objects.create(
        organization=organization,
        access_scope=scope,
        subject_key=entity.canonical_key,
        predicate="owned_by",
        value={"team": "Platform"},
        provenance=[{"type": "operator-observation", "locator": "browser evidence fixture"}],
        confidence=0.91,
        observed_at=timezone.now(),
    )
    pull_request = PullRequest.objects.create(
        organization=organization,
        repository=repository,
        number=42,
        current_head_commit="e" * 40,
    )
    run = AssuranceRun.objects.create(
        organization=organization,
        initiated_by_actor_type="SYSTEM",
        initiated_by_actor_id="test-fixture",
        repository=repository,
        repository_external_id=repository.external_id,
        pull_request_number=pull_request.number,
        head_commit=pull_request.current_head_commit,
        evaluated_commit=pull_request.current_head_commit,
        report_commit=pull_request.current_head_commit,
        policy_version=3,
        input_hash="b" * 64,
        requirements_hash="c" * 64,
        policy_bundle_hash="d" * 64,
        evidence_bundle_hash="f" * 64,
        evaluator_version="browser-evidence-v1",
        prompt_version="none-deterministic",
        limitations=[
            "No exact-commit criterion evidence artifact was supplied by the browser fixture."
        ],
        readiness="BLOCKED",
        state=AssuranceRun.State.COMPLETED,
        completed_at=timezone.now(),
    )
    AssuranceCheck.objects.create(
        organization=organization,
        assurance_run=run,
        position=1,
        code="REQUIRED_TEST_EVIDENCE",
        status=AssuranceCheck.Status.FAILED,
        blocking=True,
        summary="Required exact-commit test evidence is unavailable.",
        evidence_ids=[],
        input_hash="a" * 64,
    )
    Finding.objects.create(
        organization=organization,
        pull_request=pull_request,
        first_run=run,
        latest_run=run,
        fingerprint="9" * 64,
        code="TEST_EVIDENCE_GAP",
        kind=Finding.Kind.DETERMINISTIC,
        severity=Finding.Severity.BLOCKING,
        confidence=Finding.Confidence.PROVEN,
        title="Required test evidence is missing",
        explanation="No exact-head evidence manifest proves the repository test command passed.",
        uncertainty="The command may have run elsewhere, but no governed artifact demonstrates it.",
        suggested_resolution="Publish a commit-bound evidence manifest and re-run assurance.",
    )
    return repository, entity, assertion, run


@pytest.mark.browser
@pytest.mark.skipif(which("chromedriver") is None, reason="Chromium test stage is required")
@pytest.mark.django_db(transaction=True)
def test_primary_product_journey_and_responsive_states(live_server: object) -> None:
    """Exercise setup, search, review, assurance, diagnostics, errors, and mobile navigation."""
    base_url = str(live_server)
    driver = _chrome()
    wait = WebDriverWait(driver, 10)
    try:
        driver.get(f"{base_url}/setup")
        assert driver.find_element(By.TAG_NAME, "h1").text == (
            "Make organizational context operational."
        )
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
        wait.until(expected_conditions.url_contains("/app/onboarding"))
        assert driver.find_element(By.TAG_NAME, "h1").text == "Onboarding readiness"
        _capture(driver, "01-onboarding-desktop.png")

        repository, entity, assertion, run = _seed_product_records()

        driver.get(f"{base_url}/app")
        assert driver.find_element(By.TAG_NAME, "h1").text == "What needs a decision?"
        driver.find_element(By.TAG_NAME, "body").send_keys(Keys.TAB)
        assert driver.execute_script("return document.activeElement.tagName") == "A"
        _capture(driver, "02-attention-keyboard-focus.png")

        driver.get(f"{base_url}/app/explorer?q=payments")
        wait.until(
            expected_conditions.text_to_be_present_in_element((By.TAG_NAME, "main"), "Payments")
        )
        _capture(driver, "03-explorer-results.png")
        driver.find_element(By.CSS_SELECTOR, ".entity-list a").click()
        wait.until(
            expected_conditions.text_to_be_present_in_element(
                (By.TAG_NAME, "h1"), "Payments service"
            )
        )
        assert "Source-backed" in driver.find_element(By.TAG_NAME, "main").text
        assert driver.find_element(By.ID, "relationships-title").text == "Relationships"
        assert driver.find_elements(By.CSS_SELECTOR, "canvas") == []
        _capture(driver, "04-entity-provenance.png")

        driver.get(f"{base_url}/app/review?repository={repository.id}")
        wait.until(
            expected_conditions.text_to_be_present_in_element(
                (By.TAG_NAME, "main"), "service:payments"
            )
        )
        driver.find_element(By.CSS_SELECTOR, 'button[name="decision"][value="CONFIRM"]').click()
        wait.until(expected_conditions.url_contains("/app/review"))
        assertion.refresh_from_db()
        assert assertion.review_state == KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED
        assert "This queue is clear" in driver.find_element(By.TAG_NAME, "main").text
        _capture(driver, "05-review-confirmed.png")

        driver.get(f"{base_url}/app/assurance/{run.id}")
        assert driver.find_element(By.TAG_NAME, "h1").text == "Blocked"
        main_text = driver.find_element(By.TAG_NAME, "main").text
        assert "Required test evidence is missing" in main_text
        assert run.head_commit in main_text
        assert "No exact-commit criterion evidence artifact" in main_text
        _capture(driver, "06-assurance-blocked.png")

        driver.get(f"{base_url}/app/skills")
        skills_text = driver.find_element(By.TAG_NAME, "main").text
        assert "Non-secret diagnostics" in skills_text
        assert "test-only-bootstrap-secret" not in driver.page_source
        assert driver.find_elements(By.CSS_SELECTOR, 'input[type="password"]') == []
        assert driver.find_elements(By.CSS_SELECTOR, "[data-sensitive]") == []
        accessibility_tree = driver.execute_cdp_cmd("Accessibility.getFullAXTree", {})
        unnamed_controls = [
            node
            for node in accessibility_tree["nodes"]
            if node.get("role", {}).get("value") in {"button", "link"}
            and not node.get("name", {}).get("value")
            and not node.get("ignored", False)
        ]
        assert unnamed_controls == []
        _capture(driver, "07-skills-diagnostics.png")
        assert [
            entry
            for entry in driver.get_log("browser")  # type: ignore[no-untyped-call]
            if entry.get("level") == "SEVERE" and "favicon.ico" not in str(entry.get("message", ""))
        ] == []

        driver.get(f"{base_url}/app/explorer/entities/{uuid.uuid4()}?repository={repository.id}")
        assert driver.find_element(By.TAG_NAME, "h1").text == "This record is not available"
        assert "Correlation identifier" in driver.find_element(By.TAG_NAME, "body").text
        _capture(driver, "08-safe-error.png")

        driver.set_window_size(390, 844)
        driver.execute_cdp_cmd(
            "Emulation.setScriptExecutionDisabled",
            {"value": True},
        )
        driver.get(f"{base_url}/app")
        navigation = driver.find_element(By.CSS_SELECTOR, "[data-navigation]")
        toggle = driver.find_element(By.CSS_SELECTOR, "[data-navigation] > summary")
        assert navigation.get_attribute("open") is not None
        assert all(
            link.is_displayed()
            for link in driver.find_elements(By.CSS_SELECTOR, "[data-navigation] nav a")
        )
        toggle.click()
        wait.until(lambda _current: navigation.get_attribute("open") is None)
        toggle.click()
        wait.until(lambda _current: navigation.get_attribute("open") is not None)
        assert navigation.is_displayed()
        _capture(driver, "09-attention-mobile-navigation.png")

        driver.execute_cdp_cmd(
            "Emulation.setScriptExecutionDisabled",
            {"value": False},
        )
        assert driver.execute_script(
            "return Math.max(document.documentElement.scrollWidth, document.body.scrollWidth)"
            " <= window.innerWidth"
        )
        driver.get(f"{base_url}/app")
        navigation = driver.find_element(By.CSS_SELECTOR, "[data-navigation]")
        toggle = driver.find_element(By.CSS_SELECTOR, "[data-navigation] > summary")
        wait.until(lambda _current: navigation.get_attribute("open") is None)
        toggle.click()
        wait.until(lambda _current: navigation.get_attribute("open") is not None)

        driver.set_window_size(320, 700)
        driver.get(f"{base_url}/app/onboarding")
        driver.find_element(By.CSS_SELECTOR, "[data-navigation] > summary").click()
        assert driver.execute_script(
            "return Math.max(document.documentElement.scrollWidth, document.body.scrollWidth)"
            " <= window.innerWidth"
        )
        assert driver.find_element(By.CSS_SELECTOR, "[data-navigation] nav").is_displayed()
        _capture(driver, "10-onboarding-mobile-320.png")

        driver.set_window_size(640, 700)
        driver.get(f"{base_url}/app/onboarding")
        for _step in range(5):
            ActionChains(driver).key_down(Keys.CONTROL).send_keys("+").key_up(
                Keys.CONTROL
            ).perform()
        assert driver.execute_script(
            "return Math.max(document.documentElement.scrollWidth, document.body.scrollWidth)"
            " <= window.innerWidth"
        )
        _capture(driver, "11-onboarding-browser-zoom-200.png")

        severe_logs = [
            entry
            for entry in driver.get_log("browser")  # type: ignore[no-untyped-call]
            if entry.get("level") == "SEVERE"
            and "favicon.ico" not in str(entry.get("message", ""))
            and "404 (Not Found)" not in str(entry.get("message", ""))
        ]
        assert severe_logs == []
        assert entity.id
    finally:
        driver.quit()
