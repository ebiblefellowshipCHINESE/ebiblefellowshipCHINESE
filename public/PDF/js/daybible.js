const verses = [
    { "text": "起初，神创造天地。", "reference": "创世记 1:1" },
    { "text": "耶和华是我的牧者，我必不至缺乏。", "reference": "诗篇 23:1" },
    { "text": "神爱世人，甚至将他的独生子赐给他们，叫一切信他的，不至灭亡，反得永生。", "reference": "约翰福音 3:16" },
    { "text": "我靠着那加给我力量的，凡事都能做。", "reference": "腓立比书 4:13" },
    { "text": "耶稣说：‘我就是道路、真理、生命；若不借着我，没有人能到父那里去。’", "reference": "约翰福音 14:6" },
    { "text": "你要专心仰赖耶和华，不可倚靠自己的聪明。", "reference": "箴言 3:5" },
    { "text": "凡劳苦担重担的人，可以到我这里来，我就使你们得安息。", "reference": "马太福音 11:28" },
    { "text": "因为出于神的话，没有一句不带能力的。", "reference": "路加福音 1:37" },
    { "text": "当刚强壮胆！不要害怕，也不要惊惶；因为你无论往哪里去，耶和华你的神必与你同在。", "reference": "约书亚记 1:9" },
    { "text": "他必用自己的翎毛遮蔽你，你要投靠在他的翅膀底下。", "reference": "诗篇 91:4" },
    { "text": "要常常喜乐，不住地祷告，凡事谢恩。", "reference": "帖撒罗尼迦前书 5:16-18" },
    { "text": "义人必因信得生。", "reference": "哈巴谷书 2:4" },
    { "text": "求你将我安置在你的膀臂下，因为我知道你是我的避难所。", "reference": "诗篇 61:4" },
    { "text": "我留下平安给你们，我将我的平安赐给你们。", "reference": "约翰福音 14:27" },
    { "text": "万军之耶和华说：‘不是倚靠势力，不是倚靠才能，乃是倚靠我的灵方能成事。’", "reference": "撒迦利亚书 4:6" },
    { "text": "我们行事为人是凭着信心，不是凭着眼见。", "reference": "哥林多后书 5:7" },
    { "text": "在患难之日要投靠耶和华，他必作我们的避难所。", "reference": "诗篇 9:9" },
    { "text": "因为耶和华你的神在你中间，是施行拯救的大能者。", "reference": "西番雅书 3:17" },
    { "text": "主是我的力量，是我的盾牌；我心里倚靠他，就得帮助。", "reference": "诗篇 28:7" },
    { "text": "你要将你的事交托耶和华，并倚靠他，他就必成全。", "reference": "诗篇 37:5" },
    { "text": "你们祈求，就给你们；寻找，就寻见；叩门，就给你们开门。", "reference": "马太福音 7:7" },
    { "text": "倚靠耶和华，以耶和华为可靠的，那人有福了！", "reference": "耶利米书 17:7" },
    { "text": "耶和华是我的亮光，是我的拯救，我还怕谁呢？", "reference": "诗篇 27:1" },
    { "text": "惟有忍耐到底的必然得救。", "reference": "马太福音 24:13" },
    { "text": "所以，你们无论做什么，或说话，或行事，都要奉主耶稣的名，借着他感谢父神。", "reference": "歌罗西书 3:17" },
    { "text": "如今常存的有信、有望、有爱这三样，其中最大的是爱。", "reference": "哥林多前书 13:13" },
    { "text": "你要以感谢为祭献给神，又要向至高者还你的愿。", "reference": "诗篇 50:14" },
    { "text": "你们当刚强壮胆，不要害怕，也不要畏惧他们，因为耶和华你的神和你同去；他必不撇下你，也不丢弃你。", "reference": "申命记 31:6" },
    { "text": "主啊，求你指教我你的道，使我行在你的真理中；求你使我专心敬畏你的名。", "reference": "诗篇 86:11" },
    { "text": "凡以靠耶和华的人好像锡安山，永不动摇。", "reference": "诗篇 125:1" },
    { "text": "你们要靠主，倚赖他的大能大力作刚强的人。", "reference": "以弗所书 6:10" },
    { "text": "天离地何等的高，他的慈爱向敬畏他的人也是何等的大。", "reference": "诗篇 103:11" },
    { "text": "我们原是他的工作，在基督耶稣里造成的，为要叫我们行善，就是神所预备叫我们行的。", "reference": "以弗所书 2:10" },
    { "text": "昼夜思想耶和华律法的，这人便为有福！", "reference": "诗篇 1:2" },
    { "text": "你要以耶和华为乐，他就将你心里所求的赐给你。", "reference": "诗篇 37:4" },
    { "text": "信实的神必不叫你们受试探过于所能受的；在受试探的时候，总要给你们开一条出路，叫你们能忍受得住。", "reference": "哥林多前书 10:13" },
    { "text": "耶和华本为善；他的慈爱存到永远，他的信实直到万代。", "reference": "诗篇 100:5" },
    { "text": "耶和华的眼目看顾敬畏他的人和仰望他慈爱的人。", "reference": "诗篇 33:18" },
    { "text": "地和其中所充满的，世界和住在其间的，都属耶和华。", "reference": "诗篇 24:1" },
    { "text": "义人的道路好像黎明的光，越照越明，直到日午。", "reference": "箴言 4:18" },
    { "text": "凡事都能作，只要你信。", "reference": "马可福音 9:23" },
    { "text": "义人呼求，耶和华听见了，便救他脱离一切患难。", "reference": "诗篇 34:17" },
    { "text": "耶和华靠近伤心的人，拯救灵性痛悔的人。", "reference": "诗篇 34:18" },
    { "text": "主啊，求你创造清洁的心，使我里面重新有正直的灵。", "reference": "诗篇 51:10" },
    { "text": "耶稣基督昨日今日一直到永远是一样的。", "reference": "希伯来书 13:8" },
    { "text": "因为我的恩典够你用的，我的能力是在人的软弱上显得完全。", "reference": "哥林多后书 12:9" },
    { "text": "人心筹算自己的道路，惟耶和华指引他的脚步。", "reference": "箴言 16:9" },
    { "text": "凡求告主名的，就必得救。", "reference": "罗马书 10:13" },
    { "text": "住在至高者隐密处的，必住在全能者的荫下。", "reference": "诗篇 91:1" },
    { "text": "你们要将一切的忧虑卸给神，因为他顾念你们。", "reference": "彼得前书 5:7" },
    { "text": "愿赐平安的主随时随事亲自给你们平安。", "reference": "帖撒罗尼迦后书 3:16" },
    { "text": "因为我们行事为人，是凭着信心，不是凭着眼见。", "reference": "哥林多后书 5:7" },
    { "text": "我留下平安给你们，我将我的平安赐给你们。", "reference": "约翰福音 14:27" },
    { "text": "你们不要忧愁，因为靠耶和华而得的喜乐是你们的力量。", "reference": "尼希米记 8:10" },
    { "text": "愿耶和华赐福给你，保护你！愿耶和华使他的脸光照你，赐恩给你！愿耶和华向你仰脸，赐你平安！", "reference": "民数记 6:24-26" },
    { "text": "主所赐的喜乐，是我的力量。", "reference": "尼希米记 8:10" },
    { "text": "应当一无挂虑，只要凡事借着祷告、祈求和感谢，将你们所要的告诉神。", "reference": "腓立比书 4:6" },
    { "text": "天离地何等的高，他的慈爱向敬畏他的人也是何等的大。", "reference": "诗篇 103:11" },
    { "text": "我曾年轻，现在老了，却未见过义人被撇下，也未见过他的后裔讨饭。", "reference": "诗篇 37:25" },
    { "text": "他必用自己的翎毛遮蔽你，你要投靠在他的翅膀底下。", "reference": "诗篇 91:4" },
    { "text": "要常常喜乐，不住地祷告，凡事谢恩。", "reference": "帖撒罗尼迦前书 5:16-18" },
    { "text": "义人必因信得生。", "reference": "哈巴谷书 2:4" },
    { "text": "求你将我安置在你的膀臂下，因为我知道你是我的避难所。", "reference": "诗篇 61:4" },
    { "text": "信靠耶和华，永远的磐石。", "reference": "以赛亚书 26:3" },
    { "text": "我的恩典够你用，我的力量在你的软弱上显得完全。", "reference": "哥林多后书 12:9" }
  ]
  
  
      // 根据日期生成一个固定的随机序号
      function getDailyVerseIndex() {
        const today = new Date();
        const year = today.getFullYear();
        const month = today.getMonth() + 1; // 月份从0开始
        const day = today.getDate();
  
        // 使用日期生成唯一的索引 (哈希算法)
        const hash = year * 10000 + month * 100 + day;
        return hash % verses.length; // 保证索引在范围内
      }
  
      // 显示经文
      function showDailyVerse() {
        const index = getDailyVerseIndex();
        const verse = verses[index];
        const verseText = document.getElementById('verse-text');
        const verseReference = document.getElementById('verse-reference');
  
        // 动画显示
        verseText.style.opacity = 0;
        verseReference.style.opacity = 0;
  
        setTimeout(() => {
          verseText.textContent = verse.text;
          verseReference.textContent = verse.reference;
          verseText.style.opacity = 1;
          verseReference.style.opacity = 1;
        }, 500); // 延迟展示内容
      }
  
      // 初始化
      window.onload = showDailyVerse;