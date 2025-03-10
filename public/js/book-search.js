// 初始化 Fuse.js 搜索
const bookTitles = Array.from(document.querySelectorAll('.book-title')).map(item => item.textContent.trim());
const fuse = new Fuse(bookTitles, {
  includeScore: true,
  threshold: 0.4,
  useExtendedSearch: true,
});

// 获取 DOM 元素
const searchInput = document.getElementById('adsgarch');
const searchButton = document.getElementById('searchButton');
const dropdown = document.getElementById('dropdown');

// 音乐播放器
let audioPlayer = new Audio();
let isPlaying = false;

// 预定义音乐文件列表
const musicFiles = ["21.mp3", "31.mp3", "201.mp3", "501.mp3", "381.mp3"];
const baseURL = "http://s1.ebiblefellowship.org:40080/b/piano/";

// 监听输入框
searchInput.addEventListener('input', function () {
  handleUserInput(this.value.trim().toLowerCase());
});

// 监听搜索按钮
searchButton.addEventListener('click', function () {
  handleUserInput(searchInput.value.trim().toLowerCase());
});

// 处理用户输入
function handleUserInput(query) {
  if (query === "back") {
    window.location.href = "../index.html"; // 返回上一页
  } else if (query === "music" || query === "音乐") {
    playRandomMusic(); // 播放随机音乐
  } else if (query === "停止" || query === "break") {
    stopMusic(); // 停止音乐
  } else {
    performSearch(query); // 搜索功能
  }
}

// 搜索功能
function performSearch(query) {
  if (!query) {
    dropdown.innerHTML = '';
    return;
  }

  const results = fuse.search(query);
  renderDropdown(results);
}

// 渲染下拉菜单，添加书籍图标
function renderDropdown(results) {
  dropdown.innerHTML = '';
  if (results.length === 0) {
    const li = document.createElement('li');
    li.textContent = '无匹配结果';
    dropdown.appendChild(li);
    return;
  }
  results.forEach(result => {
    const li = document.createElement('li');
    
    // 创建 FontAwesome 书籍图标
    const icon = document.createElement('i');
    icon.className = "fas fa-book"; // FontAwesome 书籍图标
    icon.style.marginRight = "10px"; // 添加间距

    li.appendChild(icon); // 先添加图标
    li.appendChild(document.createTextNode(result.item)); // 添加文本

    li.addEventListener('click', () => {
      searchInput.value = result.item;
      dropdown.innerHTML = '';
    });

    dropdown.appendChild(li);
  });
}

// 随机播放音乐（从指定列表中选择）
function playRandomMusic() {
  if (isPlaying) return; // 防止重复播放

  let randomIndex = Math.floor(Math.random() * musicFiles.length); // 选取随机索引
  let selectedTrack = `${baseURL}${musicFiles[randomIndex]}`; // 选中的文件

  audioPlayer.src = selectedTrack;
  audioPlayer.play();
  isPlaying = true;

  console.log(`正在播放: ${selectedTrack}`);

  // 监听播放结束后停止状态
  audioPlayer.onended = function () {
    isPlaying = false;
  };
}

// 停止音乐
function stopMusic() {
  if (isPlaying) {
    audioPlayer.pause();
    audioPlayer.src = "";
    isPlaying = false;
    console.log("音乐播放已停止");
  }
}

// 关键词提取（仅供示例）
function extractKeywords(text) {
  const cleaned = text.replace(/[，。！？、]/g, ' ');
  const words = cleaned.split(/\s+/).filter(w => w.length >= 2 && w.length <= 4);
  return words;
}
