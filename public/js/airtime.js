document.addEventListener('DOMContentLoaded', () => {
    // 获取元素时增加容错处理
    const btn = document.getElementById('liveBtn');
    const wrapper = document.getElementById('liveWrapper');

    // 关键检查点
    if (!btn || !wrapper) {
        console.error('错误：缺少必要的直播控件元素');
        console.log('当前按钮状态：', btn);
        console.log('当前容器状态：', wrapper);
        return;
    }

    let isExpanded = true;

    // 初始化状态检查
    if(window.innerWidth > 768) {
        wrapper.classList.add('live-collapsed');
        isExpanded = false;
        btn.style.animation = 'pulse 1.5s infinite';
    }

    btn.addEventListener('click', () => {
        if (!wrapper) return; // 新增安全校验
        isExpanded = !isExpanded;
        wrapper.classList.toggle('live-collapsed', !isExpanded);
        btn.style.animation = isExpanded ? 'none' : 'pulse 1.5s infinite';
        btn.style.transform = isExpanded ? 'scale(0.95)' : 'scale(1)';
    });

    window.addEventListener('resize', () => {
        if (!wrapper) return; // 新增安全校验
        if(window.innerWidth > 768) {
            wrapper.classList.add('live-collapsed');
            btn.style.animation = 'pulse 1.5s infinite';
            isExpanded = false;
        } else {
            wrapper.classList.remove('live-collapsed');
            btn.style.animation = 'none';
            isExpanded = true;
        }
    });
});