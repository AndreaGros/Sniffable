const { app, BrowserWindow } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    fullscreen: true,
    autoHideMenuBar: true
  });

  win.loadFile(path.join(__dirname, 'code', 'webView', 'index.html'));
}

app.whenReady().then(createWindow);
