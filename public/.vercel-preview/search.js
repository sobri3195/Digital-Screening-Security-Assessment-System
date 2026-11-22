const form = document.querySelector('#public-search');
const input = document.querySelector('#search-query');
const results = document.querySelector('#public-results');
const resultsTitle = document.querySelector('#results-title');
const resultsQuery = document.querySelector('#results-query');
const sources = [
    { link: '#source-web', url: 'https://duckduckgo.com/', parameter: 'q' },
    { link: '#source-github', url: 'https://github.com/search?type=users', parameter: 'q' },
    { link: '#source-wikipedia', url: 'https://id.wikipedia.org/w/index.php', parameter: 'search' },
];

input.addEventListener('input', () => input.setCustomValidity(''));

form.addEventListener('submit', (event) => {
    event.preventDefault();
    const query = input.value.trim();
    if (!query) {
        input.setCustomValidity('Masukkan nama atau username.');
        input.reportValidity();
        return;
    }

    for (const source of sources) {
        const url = new URL(source.url);
        url.searchParams.set(source.parameter, query);
        document.querySelector(source.link).href = url.href;
    }

    resultsQuery.textContent = query;
    results.hidden = false;
    resultsTitle.focus();
});
