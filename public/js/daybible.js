const bibleVerses = [
  [
    {
        "verse": "起初，神创造天地。",
        "reference": "创世记 1:1"
    },
    {
        "verse": "你要专心仰赖耶和华，不可倚靠自己的聪明。",
        "reference": "箴言 3:5"
    },
    {
        "verse": "应当一无挂虑，只要凡事借着祷告、祈求，和感谢，将你们所要的告诉神。",
        "reference": "腓立比书 4:6"
    },
    {
        "verse": "因为神爱世人，甚至将他的独生子赐给他们，叫一切信他的，不至灭亡，反得永生。",
        "reference": "约翰福音 3:16"
    },
    {
        "verse": "耶和华是我的牧者，我必不至缺乏。",
        "reference": "诗篇 23:1"
    },
    {
        "verse": "凡劳苦担重担的人，可以到我这里来，我就使你们得安息。",
        "reference": "马太福音 11:28"
    },
    {
        "verse": "你要保守你心，胜过保守一切，因为一生的果效是由心发出。",
        "reference": "箴言 4:23"
    },
    {
        "verse": "人若赚得全世界，赔上自己的生命，有什么益处呢？",
        "reference": "马太福音 16:26"
    },
    {
        "verse": "我们晓得万事都互相效力，叫爱神的人得益处，就是按他旨意被召的人。",
        "reference": "罗马书 8:28"
    },
    {
        "verse": "但那等候耶和华的，必重新得力；他们必如鹰展翅上腾，他们奔跑却不困倦，行走却不疲乏。",
        "reference": "以赛亚书 40:31"
    },
    {
        "verse": "我虽然行过死荫之谷，也不怕遭害，因为你与我同在。",
        "reference": "诗篇 23:4"
    },
    {
        "verse": "不要效法这个世界，只要心意更新而变化，叫你们察验何为神的善良、纯全、可喜悦的旨意。",
        "reference": "罗马书 12:2"
    },
    {
        "verse": "义人必因信得生。",
        "reference": "罗马书 1:17"
    },
    {
        "verse": "敬畏耶和华是智慧的开端，认识至圣者便是聪明。",
        "reference": "箴言 9:10"
    },
    {
        "verse": "神是我们的避难所，是我们的力量，是我们在患难中随时的帮助。",
        "reference": "诗篇 46:1"
    },
    {
        "verse": "所以，不要为明天忧虑，因为明天自有明天的忧虑；一天的难处一天当就够了。",
        "reference": "马太福音 6:34"
    },
    {
        "verse": "你们祈求，就给你们；寻找，就寻见；叩门，就给你们开门。",
        "reference": "马太福音 7:7"
    },
    {
        "verse": "神能照着运行在我们心里的大力，充充足足地成就一切，超过我们所求所想的。",
        "reference": "以弗所书 3:20"
    },
    {
        "verse": "你们要常常喜乐，不住地祷告，凡事谢恩。",
        "reference": "帖撒罗尼迦前书 5:16-18"
    },
    {
        "verse": "耶和华所赐的福使人富足，并不加上忧虑。",
        "reference": "箴言 10:22"
    },
    {
        "verse": "住在至高者隐密处的，必住在全能者的荫下。",
        "reference": "诗篇 91:1"
    },
    {
        "verse": "主就是那灵；主的灵在哪里，那里就得以自由。",
        "reference": "哥林多后书 3:17"
    },
    {
        "verse": "义人的路好像黎明的光，越照越明，直到日午。",
        "reference": "箴言 4:18"
    },
    {
        "verse": "万军之耶和华说：“不是倚靠势力，不是倚靠才能，乃是倚靠我的灵方能成事。”",
        "reference": "撒迦利亚书 4:6"
    },
    {
        "verse": "神未曾应许天色常蓝，人生路途花香常漫。",
        "reference": "诗篇 34:19"
    },
    {
        "verse": "因为出于神的话，没有一句不带能力的。",
        "reference": "路加福音 1:37"
    },
    {
        "verse": "我已经与基督同钉十字架，现在活着的不再是我，乃是基督在我里面活着。",
        "reference": "加拉太书 2:20"
    },
    {
        "verse": "你们要以基督耶稣的心为心。",
        "reference": "腓立比书 2:5"
    },
    {
        "verse": "耶和华是我的亮光，是我的拯救，我还怕谁呢？",
        "reference": "诗篇 27:1"
    },
    {
        "verse": "使人得生命的乃是灵，肉体是无益的。",
        "reference": "约翰福音 6:63"
    },
    {
        "verse": "你们要彼此相爱，像我爱你们一样。",
        "reference": "约翰福音 13:34"
    },
    {
        "verse": "要常常喜乐。",
        "reference": "帖撒罗尼迦前书 5:16"
    },
    {
        "verse": "他医好伤心的人，裹好他们的伤处。",
        "reference": "诗篇 147:3"
    },
    {
        "verse": "耶和华所定的日子，我们在其中要高兴欢喜。",
        "reference": "诗篇 118:24"
    },
    {
        "verse": "惟有忍耐到底的，必然得救。",
        "reference": "马太福音 24:13"
    },
    {
        "verse": "神就是爱。",
        "reference": "约翰一书 4:8"
    },
    {
        "verse": "凡事都能做，但不都有益处。",
        "reference": "哥林多前书 10:23"
    }
]
];

// 获取加载文本元素、经文元素和引用元素
const loadingText = document.getElementById('loading');
const verseElement = document.getElementById('verse');
const referenceElement = document.getElementById('reference');

// 获取当前日期中的日
const today = new Date();
const dayOfMonth = today.getDate();

// 确保日期在 1 - 20 范围内
const index = (dayOfMonth - 1) % 20;

// 模拟加载延迟
setTimeout(() => {
  // 隐藏加载文本
  loadingText.style.display = 'none';

  // 设置经文和引用内容
  verseElement.textContent = bibleVerses[index].verse;
  referenceElement.textContent = bibleVerses[index].reference;
}, 1500);