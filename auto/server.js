const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3001;

app.post('/translate', async (req, res) => {
  const { text, target } = req.body;
  if (!text || !target) {
    return res.status(400).json({ error: 'Missing text or target language code' });
  }

  try {
    const response = await axios.post('https://api.example.com/translate', {
      q: text,
      target,
    });
    res.json({ translated: response.data.translatedText });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Translation failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Translate service running at http://localhost:${PORT}`);
});
