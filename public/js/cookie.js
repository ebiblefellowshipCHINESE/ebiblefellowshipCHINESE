if (document.cookie.indexOf('visited=true') === -1) {
    // 如果不存在，显示欢迎信息并设置 "visited=true" 的 cookie
    document.getElementById('welcomeMessage').style.display = 'block';
    document.cookie = "visited=true; path=/; max-age=" + 60 * 60 * 24 * 365; // 设置 cookie 有效期为一年
} else {
    // 如果 cookie 存在，隐藏欢迎信息
    document.getElementById('welcomeMessage').style.display = 'none';
}
function getCookie(name) {
    let nameEQ = name + "=";
    let ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

// 设置 cookie
function setCookie(name, value, days) {
    let date = new Date();
    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000)); // 设置有效期
    let expires = "expires=" + date.toUTCString();
    document.cookie = name + "=" + value + ";" + expires + ";path=/"; // 设置 cookie
}

// 检查是否已经同意过 cookie
if (getCookie('cookieConsent') === null) {
    // 如果没有设置 cookie，显示同意弹窗
    document.getElementById('cookieConsent').style.display = 'block';
} else {
    // 如果已经设置 cookie，隐藏同意弹窗
    document.getElementById('cookieConsent').style.display = 'none';
}

// 当用户点击 "同意" 按钮时，设置 cookie 并隐藏同意弹窗
document.getElementById('acceptButton').addEventListener('click', function() {
    // 设置 "cookieConsent" cookie，表示用户同意
    setCookie('cookieConsent', 'true', 365); // 设置有效期为一年
    // 隐藏同意弹窗
    document.getElementById('cookieConsent').style.display = 'none';
});