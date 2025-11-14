document.addEventListener('DOMContentLoaded', function() {
    const urlForm = document.getElementById('urlForm');
    const urlInput = document.getElementById('urlInput');
    const checkBtn = document.getElementById('checkBtn');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const error = document.getElementById('error');
    
    urlForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const url = urlInput.value.trim();
        
        if (!url) {
            showError('Please enter a URL to check');
            return;
        }
        
        // Hide previous results and errors
        results.classList.add('hidden');
        error.classList.add('hidden');
        
        // Show loading
        loading.classList.remove('hidden');
        checkBtn.disabled = true;
        checkBtn.textContent = 'Checking...';
        
        try {
            const response = await fetch('/check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'An error occurred');
            }
            
            // Hide loading
            loading.classList.add('hidden');
            checkBtn.disabled = false;
            checkBtn.textContent = 'Check URL';
            
            // Display results
            displayResults(data);
            
        } catch (err) {
            loading.classList.add('hidden');
            checkBtn.disabled = false;
            checkBtn.textContent = 'Check URL';
            showError(err.message || 'Failed to check URL. Please try again.');
        }
    });
    
    function displayResults(data) {
        // Display URL
        document.getElementById('urlDisplay').textContent = data.url;
        
        // Display risk level
        const riskBadge = document.getElementById('riskBadge');
        const riskLevel = document.getElementById('riskLevel');
        const riskScore = document.getElementById('riskScore');
        
        riskLevel.textContent = data.risk_level;
        riskScore.textContent = data.risk_score;
        riskBadge.style.background = data.risk_color;
        
        // Display issues
        const issuesList = document.getElementById('issuesList');
        const issueCount = document.getElementById('issueCount');
        
        issueCount.textContent = data.issue_count;
        
        if (data.issues && data.issues.length > 0) {
            issuesList.innerHTML = '';
            data.issues.forEach(issue => {
                const issueItem = document.createElement('div');
                issueItem.className = 'issue-item';
                issueItem.textContent = `⚠️ ${issue}`;
                issuesList.appendChild(issueItem);
            });
        } else {
            issuesList.innerHTML = '<div class="no-issues">✅ No issues detected! This URL appears to be safe.</div>';
        }
        
        // Show results
        results.classList.remove('hidden');
        
        // Scroll to results
        results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    
    function showError(message) {
        error.textContent = `Error: ${message}`;
        error.classList.remove('hidden');
        error.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    
    // Allow Enter key to submit
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            urlForm.dispatchEvent(new Event('submit'));
        }
    });
});

