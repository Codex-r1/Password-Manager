async function post(url, data) {
    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    return await res.json();
}

document.getElementById('setBtn').addEventListener('click', async () => {
    const domain = document.getElementById('domain').value;
    const password = document.getElementById('password').value;
    await post('/set', { domain, password });
    document.getElementById('feedback').textContent = `Password for ${domain} saved!`;
});

document.getElementById('getBtn').addEventListener('click', async () => {
    const domain = document.getElementById('domain').value;
    const result = await post('/get', { domain });
    document.getElementById('feedback').textContent = result.password || 'No password found';
});

document.getElementById('removeBtn').addEventListener('click', async () => {
    const domain = document.getElementById('domain').value;
    const result = await post('/remove', { domain });
    document.getElementById('feedback').textContent = result.success ? 'Removed!' : 'No password found';
});
