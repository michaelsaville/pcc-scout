const { contextBridge, ipcRenderer, shell } = require('electron');

contextBridge.exposeInMainWorld('collector', {
  getConfig: () => ipcRenderer.invoke('collector:config'),
  start: () => ipcRenderer.invoke('collector:start'),
  abort: () => ipcRenderer.invoke('collector:abort'),
  onProgress: (cb) => ipcRenderer.on('collector:progress', (_e, data) => cb(data)),
  onComplete: (cb) => ipcRenderer.on('collector:complete', (_e, data) => cb(data)),
  onError: (cb) => ipcRenderer.on('collector:error', (_e, msg) => cb(msg)),
  openExternal: (url) => shell.openExternal(url),
  openPath: (p) => shell.openPath(p),
  close: () => ipcRenderer.invoke('collector:close'),
});
