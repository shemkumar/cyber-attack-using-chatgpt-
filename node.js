const express = require('express');
const bodyParser = require('body-parser');
const { GPT } = require('gpt-3');

const app = express();
const gpt = new GPT({
    apiKey: 'sk-None-RL6s7W7212AKxfLaB2DnT3BlbkFJSsjhlLe98PIzJcMgKDV', // Replace with your OpenAI API key
    model: 'text-davinci-003', // Adjust model as needed
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Routes
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

app.post('/generate', async (req, res) => {
    const { prompt } = req.body;

    try {
        const response = await gpt.send({ prompt });

        res.status(200).json({ generatedResponse: response.choices[0].text });
    } catch (error) {
        console.error('Error generating response:', error);
        res.status(500).json({ error: 'Failed to generate response' });
    }
});

// Server setup
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
