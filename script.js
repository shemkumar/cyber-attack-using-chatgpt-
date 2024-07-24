document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    const generatedResponse = document.getElementById('generatedResponse');

    form.addEventListener('submit', async function(event) {
        event.preventDefault();
        
        const formData = new FormData(form);
        const prompt = formData.get('prompt');

        try {
            const response = await fetch('/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ prompt })
            });

            if (!response.ok) {
                throw new Error('Failed to generate response');
            }

            const data = await response.json();
            generatedResponse.textContent = data.generatedResponse;
        } catch (error) {
            console.error('Error:', error);
            generatedResponse.textContent = 'Error generating response';
        }
    });
});
