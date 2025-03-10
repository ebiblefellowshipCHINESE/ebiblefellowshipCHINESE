function toggleVideo() {
    var videoContainer = document.getElementById("videoContainer");
    var button = document.querySelector(".toggle-button");
    var video = document.getElementById("myVideo");

    if (videoContainer.classList.contains("hidden")) {
        videoContainer.classList.remove("hidden");
        button.textContent = "收起视频";
    } else {
        videoContainer.classList.add("hidden");
        button.textContent = "展开视频";
        video.pause(); // 关闭时暂停视频
    }
}