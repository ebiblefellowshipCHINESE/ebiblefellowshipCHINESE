function isElementInViewport(el) {
    var rect = el.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

function showClockAnimation() {
    var clockContainer = document.getElementById("clock-container");
    var clockIcon = document.getElementById("clock-icon");
    var timeText = document.getElementById("time-text");

    if (isElementInViewport(clockContainer)) {
        clockContainer.style.opacity = 1;
        clockIcon.style.animation = "rotateClock 2s linear infinite";

        setTimeout(() => {
            clockIcon.style.animation = "none";
            timeText.innerHTML = `
                星期一到星期五上午9点到10点<br><br>
                星期日凌晨两点<br><br>
                （北京时间）
            `;
        }, 2000);
    }
}