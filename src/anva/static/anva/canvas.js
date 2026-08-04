(() => {
  const recordDuration = (name, started) => {
    performance.measure(name, { start: started, end: performance.now() });
  };
  window.__anvaCanvasLongTasks = [];
  if (window.PerformanceObserver?.supportedEntryTypes?.includes("longtask")) {
    new PerformanceObserver((entries) => {
      entries.getEntries().forEach((entry) => window.__anvaCanvasLongTasks.push(entry.duration));
    }).observe({ type: "longtask", buffered: true });
  }
  const root = document.querySelector("[data-canvas-root]");
  const dataElement = document.getElementById("canvas-data");
  if (!root || !dataElement) return;

  const viewport = root.querySelector("[data-canvas-viewport]");
  const world = root.querySelector("[data-canvas-world]");
  const nodeLayer = root.querySelector("[data-canvas-nodes]");
  const edgeLayer = root.querySelector("[data-canvas-edges]");
  const minimap = root.querySelector("[data-canvas-minimap]");
  const loading = root.querySelector("[data-canvas-loading]");
  const live = root.querySelector("[data-canvas-live]");
  const zoomOutput = root.querySelector("[data-canvas-zoom]");
  const csrf = document.querySelector("[data-canvas-csrf] input[name='csrfmiddlewaretoken']");
  const filterForm = document.querySelector(".canvas-filter-form");
  const focusSelect = filterForm?.querySelector("[data-canvas-focus-select]");
  const depthSelect = filterForm?.querySelector("[data-canvas-depth-select]");
  const focusControl = root.querySelector("[data-canvas-focus]");
  const expandControl = root.querySelector("[data-canvas-expand]");
  const drawControl = root.querySelector("[data-canvas-draw-relationship]");
  const drawControls = root.querySelector("[data-canvas-draw-controls]");
  const drawStatus = root.querySelector("[data-canvas-draw-status]");
  const proposalType = root.querySelector("[data-canvas-proposal-type]");
  const proposalSubmit = root.querySelector("[data-canvas-submit-proposal]");
  const proposalPath = root.querySelector("[data-canvas-proposal-edge]");
  const proposalForm = document.querySelector("[data-canvas-proposal-form]");
  const questionForm = root.querySelector("[data-canvas-question]");
  const questionEntity = questionForm?.querySelector("[data-canvas-question-entity]");
  const annotationList = root.querySelector("[data-canvas-annotations]");
  const annotationBody = root.querySelector("[data-canvas-annotation-body]");
  const annotationControl = root.querySelector("[data-canvas-add-annotation]");
  const graph = JSON.parse(dataElement.textContent || "{}");
  const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const buttonById = new Map();
  const pathById = new Map();
  const positionById = new Map();
  let locallyVisibleIds = new Set(nodes.map((node) => node.id));
  let selectedId = null;
  let focusedId = null;
  let zoom = 1;
  let panX = 20;
  let panY = 20;
  let panning = null;
  let dragging = null;
  let dirty = false;
  let proposalMode = false;
  let proposalSourceId = null;
  let proposalTargetId = null;
  let proposalDrawing = null;
  let suppressNodeClick = false;
  let inspectorGeneration = 0;
  let inspectorController = null;
  const annotations = Array.isArray(graph.annotations) ? [...graph.annotations] : [];
  let saveIdempotencyKey = crypto.randomUUID();
  let shareIdempotencyKey = crypto.randomUUID();

  const announce = (message) => {
    if (live) live.textContent = message;
  };

  const renderAnnotations = () => {
    if (!annotationList) return;
    annotationList.replaceChildren();
    if (!annotations.length) {
      const item = document.createElement("li");
      item.textContent = "No saved presentation annotation is visible.";
      annotationList.append(item);
      return;
    }
    annotations.forEach((annotation) => {
      const item = document.createElement("li");
      const label = nodeById.get(annotation.entity_id)?.label || "View";
      item.textContent = `${label} · ${annotation.body}`;
      annotationList.append(item);
    });
  };

  const setLoading = (message) => {
    if (!loading) return;
    loading.textContent = message;
    loading.hidden = !message;
  };

  renderAnnotations();

  const proposalPoint = (id) => {
    const position = positionById.get(id);
    return position ? { x: position.x + 108, y: position.y + 42.5 } : null;
  };

  const drawProposalPath = (sourceId, targetPoint) => {
    const source = proposalPoint(sourceId);
    if (!source || !proposalPath || !targetPoint) return;
    const bend = Math.max(45, Math.abs(targetPoint.x - source.x) * 0.42);
    proposalPath.setAttribute(
      "d",
      `M ${source.x} ${source.y} C ${source.x + bend} ${source.y}, ${targetPoint.x - bend} ${targetPoint.y}, ${targetPoint.x} ${targetPoint.y}`,
    );
    proposalPath.hidden = false;
  };

  const syncProposalForm = () => {
    if (!proposalForm || !proposalSourceId || !proposalTargetId) return;
    const source = proposalForm.querySelector("select[name='source_id']");
    const target = proposalForm.querySelector("select[name='target_id']");
    const relationship = proposalForm.querySelector("select[name='relationship_type']");
    source.value = proposalSourceId;
    target.value = proposalTargetId;
    relationship.value = proposalType?.value || relationship.value;
    source.dispatchEvent(new Event("change"));
    target.dispatchEvent(new Event("change"));
  };

  const chooseProposalEndpoint = (id, { forceTarget = false } = {}) => {
    if (!proposalMode) return;
    if (!proposalSourceId || proposalTargetId || (!forceTarget && proposalSourceId === id)) {
      proposalSourceId = id;
      proposalTargetId = null;
      if (proposalSubmit) proposalSubmit.disabled = true;
      const label = nodeById.get(id)?.label || "source node";
      if (drawStatus) drawStatus.textContent = `${label} is the source. Select or drag to a different target node.`;
      drawProposalPath(id, proposalPoint(id));
      announce(`${label} selected as proposal source. Choose a target.`);
      return;
    }
    if (id === proposalSourceId) {
      announce("A relationship proposal requires a different target node.");
      return;
    }
    proposalTargetId = id;
    drawProposalPath(proposalSourceId, proposalPoint(id));
    syncProposalForm();
    if (proposalSubmit) proposalSubmit.disabled = false;
    const sourceLabel = nodeById.get(proposalSourceId)?.label || "Source";
    const targetLabel = nodeById.get(id)?.label || "target";
    if (drawStatus) {
      drawStatus.textContent = `${sourceLabel} → ${targetLabel}. Review the typed, proposal-only change before submitting.`;
    }
    announce(`${sourceLabel} to ${targetLabel} drawn as a proposal preview. Canonical knowledge is unchanged.`);
  };

  const cancelProposal = () => {
    proposalMode = false;
    proposalSourceId = null;
    proposalTargetId = null;
    proposalDrawing = null;
    if (proposalPath) proposalPath.hidden = true;
    if (proposalSubmit) proposalSubmit.disabled = true;
    if (drawControls) drawControls.hidden = true;
    drawControl?.setAttribute("aria-pressed", "false");
    root.dataset.proposalMode = "false";
    announce("Relationship proposal drawing cancelled. Canonical knowledge was unchanged.");
  };

  if (!window.dagre || !window.dagre.graphlib) {
    setLoading("The visual renderer is unavailable. The complete permitted node and relationship tables remain usable below.");
    return;
  }

  const connectedNodeIds = new Set(edges.flatMap((edge) => [edge.source, edge.target]));
  const orderedNodes = [...nodes].sort((left, right) =>
    `${left.type}:${left.id}`.localeCompare(`${right.type}:${right.id}`),
  );
  const connectedNodes = orderedNodes.filter((node) => connectedNodeIds.has(node.id));
  const layoutGraph = new window.dagre.graphlib.Graph({ multigraph: true });
  layoutGraph.setGraph({
    rankdir: "LR",
    ranker: "tight-tree",
    nodesep: 34,
    ranksep: 92,
    marginx: 80,
    marginy: 80,
  });
  layoutGraph.setDefaultEdgeLabel(() => ({}));
  connectedNodes.forEach((node) => layoutGraph.setNode(node.id, { width: 216, height: 85 }));
  [...edges]
    .sort((left, right) => `${left.type}:${left.id}`.localeCompare(`${right.type}:${right.id}`))
    .forEach((edge) => layoutGraph.setEdge(edge.source, edge.target, {}, edge.id));
  const layoutStarted = performance.now();
  if (connectedNodes.length) window.dagre.layout(layoutGraph);
  recordDuration("anva-canvas-layout", layoutStarted);

  connectedNodes.forEach((node) => {
    const computed = layoutGraph.node(node.id);
    const position = node.is_pinned
      ? node.position
      : { x: Math.max(30, computed.x - 108), y: Math.max(30, computed.y - 42.5) };
    positionById.set(node.id, { x: Number(position.x), y: Number(position.y) });
  });
  orderedNodes
    .filter((node) => !connectedNodeIds.has(node.id) && node.is_pinned)
    .forEach((node) => {
      positionById.set(node.id, {
        x: Number(node.position.x),
        y: Number(node.position.y),
      });
    });
  const unconnectedNodes = orderedNodes.filter(
    (node) => !connectedNodeIds.has(node.id) && !node.is_pinned,
  );
  const occupiedMaxX = Math.max(0, ...[...positionById.values()].map((position) => position.x));
  const unconnectedStartX = positionById.size ? occupiedMaxX + 320 : 80;
  const unconnectedColumns = Math.max(1, Math.ceil(Math.sqrt(unconnectedNodes.length * 1.5)));
  unconnectedNodes.forEach((node, index) => {
    positionById.set(node.id, {
      x: unconnectedStartX + (index % unconnectedColumns) * 250,
      y: 80 + Math.floor(index / unconnectedColumns) * 119,
    });
  });

  const worldBounds = () => {
    const values = [...positionById.values()];
    const maxX = Math.max(1200, ...values.map((position) => position.x + 280));
    const maxY = Math.max(700, ...values.map((position) => position.y + 160));
    return { width: maxX, height: maxY };
  };

  const resizeWorld = () => {
    const bounds = worldBounds();
    world.style.width = `${bounds.width}px`;
    world.style.height = `${bounds.height}px`;
  };

  const applyTransform = () => {
    world.style.transform = `translate(${panX}px, ${panY}px) scale(${zoom})`;
    zoomOutput.textContent = `${Math.round(zoom * 100)}%`;
    drawMinimap();
  };

  const updateEdges = () => {
    edges.forEach((edge) => {
      const source = positionById.get(edge.source);
      const target = positionById.get(edge.target);
      const path = pathById.get(edge.id);
      if (!source || !target || !path) return;
      path.hidden = !locallyVisibleIds.has(edge.source) || !locallyVisibleIds.has(edge.target);
      const startX = source.x + 216;
      const startY = source.y + 42;
      const endX = target.x;
      const endY = target.y + 42;
      const bend = Math.max(40, Math.abs(endX - startX) * 0.42);
      path.setAttribute(
        "d",
        `M ${startX} ${startY} C ${startX + bend} ${startY}, ${endX - bend} ${endY}, ${endX} ${endY}`,
      );
    });
  };

  const updateNodePosition = (id) => {
    const button = buttonById.get(id);
    const position = positionById.get(id);
    if (!button || !position) return;
    button.style.left = `${position.x}px`;
    button.style.top = `${position.y}px`;
  };

  const renderEdges = () => {
    edges.forEach((edge) => {
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.classList.add("canvas-edge");
      path.dataset.basis = edge.basis;
      path.dataset.freshness = edge.freshness;
      path.setAttribute("aria-hidden", "true");
      edgeLayer.append(path);
      pathById.set(edge.id, path);
    });
    if (proposalPath) edgeLayer.append(proposalPath);
    updateEdges();
  };

  const appendNodeText = (button, className, text) => {
    const span = document.createElement("span");
    span.className = className;
    span.dir = "auto";
    span.textContent = text;
    button.append(span);
  };

  const inspectorListSelectors = [
    "[data-inspector-sources]",
    "[data-inspector-relationships]",
    "[data-inspector-decisions]",
    "[data-inspector-risks]",
    "[data-inspector-work]",
    "[data-inspector-history]",
  ];

  const resetInspectorDetail = ({ summary, fieldText, listText, actionsText }) => {
    root.querySelector("[data-inspector-summary]").textContent = summary;
    [
      "[data-inspector-owner]",
      "[data-inspector-reviewers]",
      "[data-inspector-status]",
      "[data-inspector-freshness]",
      "[data-inspector-conflicts]",
    ].forEach((selector) => {
      root.querySelector(selector).textContent = fieldText;
    });
    const contextWarning = root.querySelector("[data-inspector-context]");
    contextWarning.hidden = true;
    contextWarning.textContent = "";
    inspectorListSelectors.forEach((selector) => {
      const list = root.querySelector(selector);
      const item = document.createElement("li");
      item.textContent = listText;
      list.replaceChildren(item);
    });
    root.querySelector("[data-inspector-actions]").textContent = actionsText;
  };

  const selectNode = async (id, { focus = false } = {}) => {
    const selectStarted = performance.now();
    const node = nodeById.get(id);
    const button = buttonById.get(id);
    if (!node || !button) return;
    const generation = ++inspectorGeneration;
    inspectorController?.abort();
    const controller = new AbortController();
    inspectorController = controller;
    if (selectedId && buttonById.get(selectedId)) {
      buttonById.get(selectedId).setAttribute("aria-pressed", "false");
    }
    selectedId = id;
    button.setAttribute("aria-pressed", "true");
    if (questionEntity) questionEntity.value = id;
    if (annotationControl) annotationControl.disabled = false;
    if (focusControl) focusControl.disabled = false;
    if (expandControl) expandControl.disabled = Number(depthSelect?.value || 2) >= 4;
    if (focus) button.focus();
    announce(`${node.label} selected. Loading current permitted detail.`);
    const title = root.querySelector("#canvas-inspector-title");
    title.textContent = node.label;
    title.dir = "auto";
    resetInspectorDetail({
      summary: "Loading current permitted detail…",
      fieldText: "Loading current permitted detail…",
      listText: "Loading current permitted detail…",
      actionsText: "Loading current permitted actions…",
    });
    recordDuration("anva-canvas-select-local", selectStarted);
    const repositories = (graph.repositories || [])
      .map((repository) => `repository=${encodeURIComponent(repository.id)}`)
      .join("&");
    try {
      const response = await fetch(`${root.dataset.detailEndpoint}${encodeURIComponent(id)}?${repositories}`, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (!response.ok) throw new Error("detail unavailable");
      const detail = await response.json();
      if (generation !== inspectorGeneration || selectedId !== id || controller.signal.aborted) return;
      root.querySelector("[data-inspector-summary]").textContent = detail.summary;
      root.querySelector("[data-inspector-owner]").textContent = detail.owner;
      const truncation = detail.context_truncation || {};
      const contextWarning = root.querySelector("[data-inspector-context]");
      const reviewerText = detail.reviewers.length
        ? detail.reviewers.join(", ")
        : truncation.reviewers
          ? "No reviewer was returned within the bounded permitted reviewer section."
          : "No reviewer is currently recorded.";
      root.querySelector("[data-inspector-reviewers]").textContent = truncation.reviewers
        ? `${reviewerText} Additional permitted reviewers were omitted.`
        : reviewerText;
      root.querySelector("[data-inspector-status]").textContent = detail.status;
      root.querySelector("[data-inspector-freshness]").textContent = detail.freshness;
      root.querySelector("[data-inspector-conflicts]").textContent = truncation.assertions
        ? detail.conflict_count
          ? `${detail.conflict_count} in bounded assertion context; additional permitted assertions were omitted.`
          : "None returned in bounded assertion context; additional permitted assertions were omitted."
        : String(detail.conflict_count);
      const truncatedSections = [
        ["relationships", "relationships"],
        ["decisions_policies", "decisions and policies"],
        ["risks_incidents", "risks and incidents"],
        ["active_work_recent_pull_requests", "active work and recent pull requests"],
        ["assertions", "source assertions"],
        ["history", "governed history"],
        ["reviewers", "reviewers"],
      ]
        .filter(([key]) => truncation[key])
        .map(([, label]) => label);
      contextWarning.hidden = !detail.context_truncated;
      contextWarning.textContent = detail.context_truncated
        ? `Bounded permitted context omitted additional ${truncatedSections.join(", ")}. Hidden totals and identities are not disclosed.`
        : "";
      const sourceList = root.querySelector("[data-inspector-sources]");
      sourceList.replaceChildren();
      if (!detail.sources.length) {
        const item = document.createElement("li");
        item.textContent = "No current normalized source citation is available.";
        sourceList.append(item);
      }
      detail.sources.forEach((source) => {
        const item = document.createElement("li");
        const citation = source.citations.length
          ? ` · ${source.citations.map((entry) => entry.locator || "Source").join(", ")}`
          : " · current citation unavailable";
        item.textContent = `${source.predicate} · ${source.freshness} · ${source.review_state}${citation}`;
        sourceList.append(item);
      });
      if (truncation.assertions) {
        const item = document.createElement("li");
        item.textContent = "Additional permitted source assertions were omitted at the section bound.";
        sourceList.append(item);
      }
      const renderDetailList = (selector, items, emptyText, describe, truncated, sectionName) => {
        const list = root.querySelector(selector);
        list.replaceChildren();
        if (!items.length) {
          const item = document.createElement("li");
          item.textContent = truncated
            ? `No ${sectionName} item was returned within this bounded permitted section; additional permitted context was omitted.`
            : emptyText;
          list.append(item);
          return;
        }
        items.forEach((entry) => {
          const item = document.createElement("li");
          item.textContent = describe(entry);
          list.append(item);
        });
        if (truncated) {
          const item = document.createElement("li");
          item.textContent = `Additional permitted ${sectionName} items were omitted at the section bound.`;
          list.append(item);
        }
      };
      renderDetailList(
        "[data-inspector-relationships]",
        detail.relationships,
        "No current permitted relationship is connected to this entity.",
        (entry) => `${entry.direction} · ${entry.type} · ${entry.source_label} → ${entry.target_label}`,
        truncation.relationships,
        "relationship",
      );
      renderDetailList(
        "[data-inspector-decisions]",
        detail.decisions_policies,
        "No connected decision or policy is currently permitted.",
        (entry) => `${entry.type} · ${entry.label} · ${entry.status}`,
        truncation.decisions_policies,
        "decision or policy",
      );
      renderDetailList(
        "[data-inspector-risks]",
        detail.risks_incidents,
        "No connected risk or incident is currently permitted.",
        (entry) => `${entry.type} · ${entry.label} · ${entry.status}`,
        truncation.risks_incidents,
        "risk or incident",
      );
      renderDetailList(
        "[data-inspector-work]",
        [...detail.active_work, ...detail.recent_pull_requests],
        "No connected active work or recent pull request is currently permitted.",
        (entry) => `${entry.type} · ${entry.label} · ${entry.status}`,
        truncation.active_work_recent_pull_requests,
        "active work or recent pull request",
      );
      renderDetailList(
        "[data-inspector-history]",
        detail.history,
        "No authorized assertion revision history is available.",
        (entry) => `${entry.predicate} · revision ${entry.revision} · ${entry.created_at}`,
        truncation.history,
        "governed history",
      );
      root.querySelector("[data-inspector-actions]").textContent = detail.permitted_actions.propose_relationship
        ? "View layout may be saved separately. Relationship changes require a review proposal. Canonical deletion is unavailable here."
        : "Current role can inspect this entity. Canonical mutation and deletion are unavailable here.";
      announce(`${detail.label} detail loaded. Freshness ${detail.freshness}.`);
    } catch (_error) {
      if (generation !== inspectorGeneration || selectedId !== id) return;
      resetInspectorDetail({
        summary: "Current detail is unavailable. Access may have changed; no stale detail was retained.",
        fieldText: "Current detail unavailable.",
        listText: "Current permitted detail unavailable.",
        actionsText: "Current permitted actions unavailable.",
      });
      announce("Current permitted detail is unavailable.");
    } finally {
      if (generation === inspectorGeneration) inspectorController = null;
    }
  };

  const nearestNode = (id, key) => {
    const origin = positionById.get(id);
    if (!origin) return null;
    const candidates = [...positionById.entries()].filter(([candidateId, position]) => {
      if (candidateId === id) return false;
      if (!locallyVisibleIds.has(candidateId)) return false;
      if (key === "ArrowLeft") return position.x < origin.x;
      if (key === "ArrowRight") return position.x > origin.x;
      if (key === "ArrowUp") return position.y < origin.y;
      return position.y > origin.y;
    });
    candidates.sort((left, right) => {
      const leftDistance = Math.hypot(left[1].x - origin.x, left[1].y - origin.y);
      const rightDistance = Math.hypot(right[1].x - origin.x, right[1].y - origin.y);
      return leftDistance - rightDistance || left[0].localeCompare(right[0]);
    });
    return candidates[0]?.[0] || null;
  };

  const renderNodes = () => {
    nodes.forEach((node, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "canvas-node";
      button.dataset.nodeId = node.id;
      button.dataset.freshness = node.freshness;
      button.dataset.conflict = String(node.has_conflict);
      button.setAttribute("aria-pressed", "false");
      button.setAttribute(
        "aria-label",
        `${node.label}, ${node.type}, ${node.freshness}, ${node.is_inferred ? "inferred" : node.provenance.kind}`,
      );
      button.tabIndex = index === 0 ? 0 : -1;
      appendNodeText(button, "canvas-node__type", node.type.replaceAll("_", " "));
      appendNodeText(button, "canvas-node__name", node.label);
      appendNodeText(
        button,
        "canvas-node__meta",
        `${node.freshness} · ${node.owner || "unassigned"}${node.has_conflict ? " · conflict" : ""}`,
      );
      button.addEventListener("click", () => {
        if (suppressNodeClick) return;
        if (proposalMode) chooseProposalEndpoint(node.id);
        selectNode(node.id);
      });
      button.addEventListener("focus", () => {
        focusedId = node.id;
        buttonById.forEach((item, candidateId) => {
          item.tabIndex = candidateId === node.id ? 0 : -1;
        });
      });
      button.addEventListener("keydown", (event) => {
        if (["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) {
          event.preventDefault();
          const nextId = nearestNode(node.id, event.key);
          if (nextId) buttonById.get(nextId).focus();
        } else if (event.key === "Home") {
          event.preventDefault();
          buttonById.get(nodes[0]?.id)?.focus();
        } else if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          if (proposalMode) chooseProposalEndpoint(node.id);
          selectNode(node.id);
        } else if (event.key === "Escape") {
          event.preventDefault();
          if (proposalMode) cancelProposal();
          viewport.focus();
        }
      });
      button.addEventListener("pointerdown", (event) => {
        if (event.button !== 0) return;
        event.stopPropagation();
        button.setPointerCapture(event.pointerId);
        if (proposalMode) {
          proposalSourceId = null;
          proposalTargetId = null;
          proposalDrawing = { sourceId: node.id, pointerId: event.pointerId };
          chooseProposalEndpoint(node.id);
          return;
        }
        const position = positionById.get(node.id);
        dragging = {
          id: node.id,
          pointerId: event.pointerId,
          startX: event.clientX,
          startY: event.clientY,
          x: position.x,
          y: position.y,
        };
      });
      button.addEventListener("pointermove", (event) => {
        if (proposalDrawing?.pointerId === event.pointerId) {
          const rect = viewport.getBoundingClientRect();
          drawProposalPath(proposalDrawing.sourceId, {
            x: (event.clientX - rect.left - panX) / zoom,
            y: (event.clientY - rect.top - panY) / zoom,
          });
          return;
        }
        if (!dragging || dragging.pointerId !== event.pointerId) return;
        const x = dragging.x + (event.clientX - dragging.startX) / zoom;
        const y = dragging.y + (event.clientY - dragging.startY) / zoom;
        positionById.set(dragging.id, { x: Math.max(0, x), y: Math.max(0, y) });
        updateNodePosition(dragging.id);
        resizeWorld();
        updateEdges();
        dirty = true;
        drawMinimap();
      });
      button.addEventListener("pointerup", (event) => {
        if (proposalDrawing?.pointerId === event.pointerId) {
          const target = document.elementFromPoint(event.clientX, event.clientY)?.closest(".canvas-node");
          proposalDrawing = null;
          if (target?.dataset.nodeId) {
            chooseProposalEndpoint(target.dataset.nodeId, { forceTarget: true });
          } else if (proposalSourceId) {
            drawProposalPath(proposalSourceId, proposalPoint(proposalSourceId));
          }
          suppressNodeClick = true;
          setTimeout(() => {
            suppressNodeClick = false;
          }, 0);
          return;
        }
        if (dragging?.pointerId !== event.pointerId) return;
        dragging = null;
        announce(`${node.label} moved in this view only. Save layout to create a new presentation revision.`);
      });
      nodeLayer.append(button);
      buttonById.set(node.id, button);
      updateNodePosition(node.id);
    });
  };

  const applyLocalFilters = () => {
    if (!filterForm) return;
    const started = performance.now();
    const search = (filterForm.querySelector("input[name='q']")?.value || "").trim().toLocaleLowerCase();
    const freshness = filterForm.querySelector("select[name='freshness']")?.value || "";
    const owner = (filterForm.querySelector("input[name='owner']")?.value || "").trim().toLocaleLowerCase();
    const status = (filterForm.querySelector("input[name='status']")?.value || "").trim().toLocaleLowerCase();
    const risk = (filterForm.querySelector("input[name='risk']")?.value || "").trim().toLocaleLowerCase();
    const selectedTypes = new Set(
      [...(filterForm.querySelector("select[name='type']")?.selectedOptions || [])].map(
        (option) => option.value,
      ),
    );
    locallyVisibleIds = new Set();
    nodes.forEach((node) => {
      const searchable = `${node.label} ${node.canonical_key} ${node.type} ${node.owner} ${node.status} ${node.risk}`.toLocaleLowerCase();
      const visible =
        (!search || searchable.includes(search)) &&
        (!freshness || node.freshness === freshness) &&
        (!owner || String(node.owner || "").toLocaleLowerCase().includes(owner)) &&
        (!status || String(node.status || "").toLocaleLowerCase().includes(status)) &&
        (!risk || String(node.risk || "").toLocaleLowerCase().includes(risk)) &&
        (!selectedTypes.size || selectedTypes.has(node.type));
      buttonById.get(node.id).hidden = !visible;
      document.querySelector(`[data-table-node="${CSS.escape(node.id)}"]`)?.closest("tr")?.toggleAttribute("hidden", !visible);
      if (visible) locallyVisibleIds.add(node.id);
    });
    updateEdges();
    recordDuration("anva-canvas-filter-local", started);
    announce(
      `${locallyVisibleIds.size} permitted nodes match locally. Apply view to rerun the authorized server projection.`,
    );
  };

  filterForm?.querySelectorAll("input[name='q'], input[name='owner'], input[name='status'], input[name='risk']").forEach((control) =>
    control.addEventListener("input", applyLocalFilters),
  );
  filterForm?.querySelectorAll("select[name='freshness'], select[name='type']").forEach((control) =>
    control.addEventListener("change", applyLocalFilters),
  );

  focusControl?.addEventListener("click", () => {
    if (!selectedId || !focusSelect || !filterForm) return;
    focusSelect.value = selectedId;
    filterForm.requestSubmit();
  });

  expandControl?.addEventListener("click", () => {
    if (!selectedId || !focusSelect || !depthSelect || !filterForm) return;
    focusSelect.value = selectedId;
    depthSelect.value = String(Math.min(4, Number(depthSelect.value || 2) + 1));
    filterForm.requestSubmit();
  });

  annotationControl?.addEventListener("click", () => {
    const body = annotationBody?.value.trim();
    const position = selectedId ? positionById.get(selectedId) : null;
    if (!selectedId || !body || !position) return;
    annotations.push({
      entity_id: selectedId,
      body,
      x: position.x,
      y: position.y,
    });
    annotationBody.value = "";
    dirty = true;
    renderAnnotations();
    announce("Annotation added to this layout. Save layout to create an immutable presentation revision.");
  });

  function drawMinimap() {
    if (!minimap || minimap.hidden) return;
    const context = minimap.getContext("2d");
    const bounds = worldBounds();
    const scale = Math.min(minimap.width / bounds.width, minimap.height / bounds.height);
    context.clearRect(0, 0, minimap.width, minimap.height);
    context.fillStyle = "#0b110f";
    context.fillRect(0, 0, minimap.width, minimap.height);
    context.fillStyle = "#70d8c0";
    positionById.forEach((position, id) => {
      context.fillStyle = id === selectedId ? "#b9f56a" : "#70d8c0";
      context.fillRect(position.x * scale, position.y * scale, 5, 3);
    });
    context.strokeStyle = "#f3f0e7";
    context.lineWidth = 1;
    context.strokeRect(
      Math.max(0, -panX / zoom) * scale,
      Math.max(0, -panY / zoom) * scale,
      (viewport.clientWidth / zoom) * scale,
      (viewport.clientHeight / zoom) * scale,
    );
  }

  const setZoom = (value, centerX = viewport.clientWidth / 2, centerY = viewport.clientHeight / 2) => {
    const next = Math.min(2.5, Math.max(0.25, value));
    const worldX = (centerX - panX) / zoom;
    const worldY = (centerY - panY) / zoom;
    panX = centerX - worldX * next;
    panY = centerY - worldY * next;
    zoom = next;
    applyTransform();
  };

  const fit = () => {
    if (!nodes.length) return;
    const bounds = worldBounds();
    zoom = Math.min(1.2, Math.max(0.25, Math.min(viewport.clientWidth / bounds.width, viewport.clientHeight / bounds.height) * 0.92));
    panX = Math.max(12, (viewport.clientWidth - bounds.width * zoom) / 2);
    panY = Math.max(12, (viewport.clientHeight - bounds.height * zoom) / 2);
    applyTransform();
    announce(`Canvas fitted at ${Math.round(zoom * 100)} percent.`);
  };

  viewport.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || event.target.closest(".canvas-node")) return;
    viewport.setPointerCapture(event.pointerId);
    panning = { pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, x: panX, y: panY };
    viewport.dataset.panning = "true";
  });
  viewport.addEventListener("pointermove", (event) => {
    if (!panning || panning.pointerId !== event.pointerId) return;
    panX = panning.x + event.clientX - panning.startX;
    panY = panning.y + event.clientY - panning.startY;
    applyTransform();
  });
  viewport.addEventListener("pointerup", (event) => {
    if (panning?.pointerId !== event.pointerId) return;
    panning = null;
    viewport.dataset.panning = "false";
  });
  viewport.addEventListener(
    "wheel",
    (event) => {
      const gestureStarted = performance.now();
      event.preventDefault();
      const rect = viewport.getBoundingClientRect();
      setZoom(zoom * (event.deltaY > 0 ? 0.9 : 1.1), event.clientX - rect.left, event.clientY - rect.top);
      recordDuration("anva-canvas-gesture-main-thread", gestureStarted);
      requestAnimationFrame(() => recordDuration("anva-canvas-gesture-frame", gestureStarted));
    },
    { passive: false },
  );
  viewport.addEventListener("keydown", (event) => {
    const panStep = event.shiftKey ? 70 : 25;
    if (["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) {
      event.preventDefault();
      if (event.key === "ArrowLeft") panX += panStep;
      if (event.key === "ArrowRight") panX -= panStep;
      if (event.key === "ArrowUp") panY += panStep;
      if (event.key === "ArrowDown") panY -= panStep;
      applyTransform();
    } else if (event.key === "+" || event.key === "=") {
      event.preventDefault();
      setZoom(zoom * 1.15);
    } else if (event.key === "-") {
      event.preventDefault();
      setZoom(zoom / 1.15);
    } else if (event.key === "0") {
      event.preventDefault();
      fit();
    } else if (event.key === "Home" && nodes.length) {
      event.preventDefault();
      buttonById.get(nodes[0].id).focus();
    }
  });

  root.querySelector("[data-canvas-zoom-in]")?.addEventListener("click", () => setZoom(zoom * 1.15));
  root.querySelector("[data-canvas-zoom-out]")?.addEventListener("click", () => setZoom(zoom / 1.15));
  root.querySelector("[data-canvas-fit]")?.addEventListener("click", fit);
  root.querySelector("[data-canvas-minimap-toggle]")?.addEventListener("click", (event) => {
    minimap.hidden = !minimap.hidden;
    event.currentTarget.setAttribute("aria-pressed", String(!minimap.hidden));
    drawMinimap();
  });
  drawControl?.addEventListener("click", () => {
    if (proposalMode) {
      cancelProposal();
      return;
    }
    proposalMode = true;
    proposalSourceId = null;
    proposalTargetId = null;
    root.dataset.proposalMode = "true";
    drawControl.setAttribute("aria-pressed", "true");
    if (drawControls) drawControls.hidden = false;
    if (drawStatus) {
      drawStatus.textContent = "Select or drag from a source node, then select or drag to a target. No canonical relationship will be changed.";
    }
    announce("Relationship proposal drawing enabled. Choose a source node and a target node.");
    buttonById.get(focusedId || nodes[0]?.id)?.focus();
  });
  root.querySelector("[data-canvas-cancel-proposal]")?.addEventListener("click", cancelProposal);
  proposalType?.addEventListener("change", syncProposalForm);
  proposalSubmit?.addEventListener("click", () => {
    if (!proposalSourceId || !proposalTargetId || !proposalForm) return;
    syncProposalForm();
    const details = proposalForm.closest("details");
    if (details) details.open = true;
    proposalForm.querySelector("textarea[name='rationale']")?.focus();
    proposalForm.scrollIntoView({ behavior: "smooth", block: "center" });
    announce("Proposal preview copied to the governed form. Add a rationale and submit for review; canonical knowledge remains unchanged.");
  });

  document.querySelectorAll("[data-table-node]").forEach((button) => {
    button.addEventListener("click", () => {
      if (proposalMode) chooseProposalEndpoint(button.dataset.tableNode);
      selectNode(button.dataset.tableNode, { focus: true });
    });
  });

  const requestHeaders = () => ({
    "Content-Type": "application/json",
    "X-CSRFToken": csrf?.value || "",
  });

  questionForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const results = root.querySelector("[data-canvas-question-results]");
    const repository = questionForm.querySelector("[data-canvas-question-repository]")?.value;
    const question = questionForm.querySelector("[data-canvas-question-text]")?.value.trim();
    const entityId = questionEntity?.value;
    if (!results || !repository || !question || !entityId) return;
    results.replaceChildren();
    const loadingItem = document.createElement("li");
    loadingItem.textContent = "Retrieving authorized evidence…";
    results.append(loadingItem);
    try {
      const response = await fetch(root.dataset.questionEndpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: requestHeaders(),
        body: JSON.stringify({
          entity_id: entityId,
          repository_id: repository,
          question,
        }),
      });
      if (!response.ok) throw new Error("question unavailable");
      const payload = await response.json();
      results.replaceChildren();
      if (!payload.results.length) {
        const item = document.createElement("li");
        item.textContent = payload.limitation;
        results.append(item);
      }
      payload.results.forEach((result) => {
        const item = document.createElement("li");
        item.textContent = `${result.text} · ${result.canonical_url}`;
        results.append(item);
      });
      announce(`Selection-scoped evidence retrieved for ${payload.entity.label}.`);
    } catch (_error) {
      results.replaceChildren();
      const item = document.createElement("li");
      item.textContent = "Scoped evidence is unavailable. Access may have changed.";
      results.append(item);
      announce("Selection-scoped evidence could not be retrieved.");
    }
  });

  root.querySelector("[data-canvas-save]")?.addEventListener("click", async (event) => {
    const control = event.currentTarget;
    control.disabled = true;
    control.textContent = "Saving…";
    const presentation = {
      placements: nodes.map((node) => ({
        entity_id: node.id,
        x: positionById.get(node.id).x,
        y: positionById.get(node.id).y,
        is_pinned: true,
        is_hidden: false,
        group_index: null,
      })),
      filters: [],
      layers: [],
      groups: [],
      annotations: annotations.map((annotation) => ({
        entity_id: annotation.entity_id || null,
        body: annotation.body,
        x: Number(annotation.x),
        y: Number(annotation.y),
      })),
    };
    try {
      const response = await fetch(root.dataset.saveEndpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: requestHeaders(),
        body: JSON.stringify({
          expected_revision: graph.view.revision,
          semantic_query: graph.semantic_query || {},
          presentation,
          idempotency_key: saveIdempotencyKey,
        }),
      });
      if (!response.ok) throw new Error("save failed");
      const result = await response.json();
      dirty = false;
      graph.view.revision = result.revision;
      saveIdempotencyKey = crypto.randomUUID();
      control.textContent = `Saved r${result.revision}`;
      announce(`Layout saved as presentation revision ${result.revision}. Canonical knowledge was unchanged.`);
    } catch (_error) {
      control.textContent = "Save current layout";
      announce("Layout was not saved. Reload the current revision before retrying.");
    } finally {
      control.disabled = false;
    }
  });

  root.querySelector("[data-canvas-share]")?.addEventListener("click", async (event) => {
    const control = event.currentTarget;
    control.disabled = true;
    try {
      const response = await fetch(root.dataset.shareEndpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: requestHeaders(),
        body: JSON.stringify({ idempotency_key: shareIdempotencyKey }),
      });
      if (!response.ok) throw new Error("share failed");
      const result = await response.json();
      shareIdempotencyKey = crypto.randomUUID();
      const absolute = new URL(result.deep_link, window.location.origin).toString();
      await navigator.clipboard?.writeText(absolute);
      control.textContent = "Link copied";
      announce("Sign-in-required deep link copied. It grants no additional access.");
    } catch (_error) {
      control.textContent = "Share";
      announce("A deep link could not be created.");
    } finally {
      control.disabled = false;
    }
  });

  const updateProposalRevisions = () => {
    if (!proposalForm) return;
    const source = proposalForm.querySelector("select[name='source_id']").selectedOptions[0];
    const target = proposalForm.querySelector("select[name='target_id']").selectedOptions[0];
    proposalForm.querySelector("[data-source-revision]").value = source?.dataset.revision || "1";
    proposalForm.querySelector("[data-target-revision]").value = target?.dataset.revision || "1";
  };
  proposalForm?.querySelector("select[name='source_id']")?.addEventListener("change", updateProposalRevisions);
  proposalForm?.querySelector("select[name='target_id']")?.addEventListener("change", updateProposalRevisions);
  updateProposalRevisions();

  resizeWorld();
  renderNodes();
  renderEdges();
  setLoading("");
  fit();
  recordDuration("anva-canvas-shell-interactive", 0);
  document.documentElement.dataset.canvasInteractive = "true";
  if (!nodes.length) announce("No permitted nodes match this Canvas view.");
  window.addEventListener("beforeunload", (event) => {
    if (!dirty) return;
    event.preventDefault();
  });
})();
