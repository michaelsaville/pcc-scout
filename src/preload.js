const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  // Config
  configLoad: () => ipcRenderer.invoke('config:load'),
  configSave: (config) => ipcRenderer.invoke('config:save', config),

  // Scanner
  scannerStart: (opts) => ipcRenderer.invoke('scanner:start', opts),
  onScannerProgress: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('scanner:progress', handler);
    return () => ipcRenderer.removeListener('scanner:progress', handler);
  },
  onScannerComplete: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('scanner:complete', handler);
    return () => ipcRenderer.removeListener('scanner:complete', handler);
  },
  onScannerError: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('scanner:error', handler);
    return () => ipcRenderer.removeListener('scanner:error', handler);
  },

  // Report
  reportGenerate: (opts) => ipcRenderer.invoke('report:generate', opts),
  onReportComplete: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('report:complete', handler);
    return () => ipcRenderer.removeListener('report:complete', handler);
  },

  // Dialogs
  dialogOpenFile: () => ipcRenderer.invoke('dialog:openFile'),
  shellOpenPath: (dirPath) => ipcRenderer.invoke('shell:openPath', dirPath),
});
