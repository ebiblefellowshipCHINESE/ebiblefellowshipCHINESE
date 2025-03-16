document.addEventListener("DOMContentLoaded", function () {
    const loadingText = document.getElementById('loading');
    const verseElement = document.getElementById('verse');
    const referenceElement = document.getElementById('reference');

    // 确保 HTML ID 没有拼写错误
    if (!loadingText || !verseElement || !referenceElement) {
        console.error("无法找到某些 HTML 元素，请检查 ID 是否正确");
        return;
    }

    // 修正：使用 `verse` 而不是 `bibleVerses`
    const verse = [
        { "verse": "起初，神创造天地。", "reference": "创世记 1:1" },
        { "verse": "你要专心仰赖耶和华，不可倚靠自己的聪明。", "reference": "箴言 3:5" },
        { "verse": "应当一无挂虑，只要凡事借着祷告、祈求，和感谢，将你们所要的告诉神。", "reference": "腓立比书 4:6" },
        { "verse": "因为神爱世人，甚至将他的独生子赐给他们，叫一切信他的，不至灭亡，反得永生。", "reference": "约翰福音 3:16" },
        { "verse": "耶和华是我的牧者，我必不至缺乏。", "reference": "诗篇 23:1" },
        { "verse": "凡劳苦担重担的人，可以到我这里来，我就使你们得安息。", "reference": "马太福音 11:28" },
        { "verse": "你要保守你心，胜过保守一切，因为一生的果效是由心发出。", "reference": "箴言 4:23" },
        { "verse": "人若赚得全世界，赔上自己的生命，有什么益处呢？", "reference": "马太福音 16:26" },
        { "verse": "我们晓得万事都互相效力，叫爱神的人得益处，就是按他旨意被召的人。", "reference": "罗马书 8:28" },
        { "verse": "但那等候耶和华的，必重新得力；他们必如鹰展翅上腾，他们奔跑却不困倦，行走却不疲乏。", "reference": "以赛亚书 40:31" },
        { "verse": "所以，不要为明天忧虑，因为明天自有明天的忧虑；一天的难处一天当就够了。", "reference": "马太福音 6:34" },
        { "verse": "你们祈求，就给你们；寻找，就寻见；叩门，就给你们开门。", "reference": "马太福音 7:7" },
        { "verse": "你们要常常喜乐，不住地祷告，凡事谢恩。", "reference": "帖撒罗尼迦前书 5:16-18" }
    ];

    // 获取当前日期
    const today = new Date();
    const dayOfMonth = today.getDate();

    // 修正：确保 `index` 不超过 `verse` 的长度
    const index = (dayOfMonth - 1) % verse.length;

    // 模拟加载延迟
    setTimeout(() => {
        loadingText.style.display = 'none';
        verseElement.textContent = verse[index].verse;
        referenceElement.textContent = verse[index].reference;
    }, 1500);
});