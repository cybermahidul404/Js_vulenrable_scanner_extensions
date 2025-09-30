// Function to fetch subdomains from crt.sh
function fetchSubdomains(domain) {
    const subdomainSet = new Set();
    
    fetch(`https://crt.sh/?q=%25.${domain}&output=json`)
      .then(response => response.json())
      .then(data => {
        data.forEach(entry => {
          const subdomains = entry.name_value.split('\n');
          subdomains.forEach(sub => {
            if (sub.includes(domain)) {
              subdomainSet.add(sub.trim());
            }
          });
        });
        // Send the subdomains back to the background script
        chrome.runtime.sendMessage({ type: 'subdomains', data: Array.from(subdomainSet) });
      })
      .catch(err => console.log('Error fetching subdomains:', err));
  }
  
  // Extract the domain from the current window's URL
  const currentDomain = window.location.hostname.split('.').slice(-2).join('.');
  fetchSubdomains(currentDomain);