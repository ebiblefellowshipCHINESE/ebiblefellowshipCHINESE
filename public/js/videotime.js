function changeVideo(videoSource) {
    var videoPlayer = document.getElementById('videoPlayer');
    videoPlayer.src = videoSource;
    videoPlayer.play();

    // 设置视频描述
    var descriptionText = '';
    switch(videoSource) {
        case 'video1.mp4':
            descriptionText = '观看部分 1 的历史内容。';
            break;
        case 'video2.mp4':
            descriptionText = '观看部分 2 的历史内容。';
            break;
        case 'video3.mp4':
            descriptionText = '观看部分 3 的历史内容。';
            break;
        case 'video4.mp4':
            descriptionText = '观看部分 4 的历史内容。';
            break;
        default:
            descriptionText = '选择一个视频进行观看。';
    }
    document.getElementById('videoDescription').innerText = descriptionText;
}

// 使视频内容收缩和展开
var toggleBox = document.getElementById('toggleContent');
toggleBox.addEventListener('click', function() {
    toggleBox.classList.toggle('collapsed');
});