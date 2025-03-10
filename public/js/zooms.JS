function isElementInViewport(el) {
    var rect = el.getBoundingClientRect();
    return rect.top < window.innerHeight && rect.bottom > 0;
}

function showSchedule() {
    var scheduleContainer = document.getElementById("schedule-container");

    if (isElementInViewport(scheduleContainer)) {
        scheduleContainer.style.opacity = 1;
        document.removeEventListener("scroll", showSchedule); // 只触发一次
    }
}

document.addEventListener("scroll", showSchedule);
window.addEventListener("load", showSchedule);