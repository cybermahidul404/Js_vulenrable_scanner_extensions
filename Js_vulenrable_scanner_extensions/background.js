chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'jsFiles') {
      // Log the JS files received
      console.log('JS files:', message.data);
  
      // Store the JS files in local storage
      chrome.storage.local.set({ jsFiles: message.data });
    }
    if (message.type === 'subdomains') {
      // Save subdomains to local storage
      chrome.storage.local.set({ subdomains: message.data });
    }
  });