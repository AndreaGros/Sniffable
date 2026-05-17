const { app, BrowserWindow } = require('electron');
const path = require('path');

app.commandLine.appendSwitch('enable-features', 'UseOzonePlatform');
app.commandLine.appendSwitch('ozone-platform', 'wayland');

function createWindow() {
  const win = new BrowserWindow({
    alwaysOnTop: false,
    fullscreen: true,
    autoHideMenuBar: true
  });

  win.loadFile(path.join(__dirname, 'code', 'webView', 'index.html'));
}

app.whenReady().then(createWindow);
