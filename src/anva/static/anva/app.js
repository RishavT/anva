const message = document.querySelector("[data-health-message]");
const indicator = document.querySelector("[data-health-indicator]");
const retry = document.querySelector("[data-health-retry]");

async function checkHealth() {
  message.textContent = "Checking service readiness…";
  indicator.dataset.state = "checking";
  retry.hidden = true;

  try {
    const response = await fetch("/health/ready", {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error("readiness check failed");
    }
    message.textContent = "All foundation services are ready";
    indicator.dataset.state = "ready";
  } catch {
    message.textContent = "A required service is unavailable";
    indicator.dataset.state = "unavailable";
    retry.hidden = false;
  }
}

retry.addEventListener("click", checkHealth);
checkHealth();
