document.addEventListener('DOMContentLoaded', () => {

    const accountForm = document.getElementById('account-settings-form');
    const terminalForm = document.getElementById('terminal-settings-form');

    const showMessage = (message, isError = false) => {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', isError ? 'error' : 'success');
        messageDiv.textContent = message;

        document.querySelectorAll('.message').forEach(el => el.remove());
        
        const container = document.querySelector('.container');
        if (container) {
            container.insertBefore(messageDiv, container.firstChild);
        } else {
            document.body.insertBefore(messageDiv, document.body.firstChild);
        }

        setTimeout(() => messageDiv.remove(), 5000);
    };

    if (accountForm) {
        accountForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const firstName = accountForm.querySelector('#firstName').value;
            const lastName = accountForm.querySelector('#lastName').value;
            const email = accountForm.querySelector('#email').value;

            try {
                const response = await fetch('/api/update-user-settings', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ firstName, lastName, email }),
                });
                const result = await response.json();

                if (response.ok) {
                    showMessage(result.message || 'Settings updated successfully!');
                } else {
                    showMessage(result.message || 'Failed to update settings.', true);
                }
            } catch (error) {
                console.error('Error:', error);
                showMessage('An error occurred. Please try again.', true);
            }
        });
    }

    if (terminalForm) {
        terminalForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const fontSize = terminalForm.querySelector('#fontSize').value;
            const fontColor = terminalForm.querySelector('#fontColor').value;
            const backgroundColor = terminalForm.querySelector('#backgroundColor').value;

            try {
                const response = await fetch('/api/update-user-settings', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ fontSize, fontColor, backgroundColor }),
                });
                const result = await response.json();

                if (response.ok) {
                    showMessage(result.message || 'Terminal settings updated successfully!');
                } else {
                    showMessage(result.message || 'Failed to update terminal settings.', true);
                }
            } catch (error) {
                console.error('Error:', error);
                showMessage('An error occurred. Please try again.', true);
            }
        });
    }
});