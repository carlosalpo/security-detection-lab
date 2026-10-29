// Recipe for the CUA REPL. This is not a standalone browser driver.
// First invocation only; read the returned documentation before continuing:
// let tab = await cua.createBrowserTab('iab', 'about:blank', {visible:false});
// Serve the publish directory on loopback using python -m http.server.
// In a later invocation, choose a NEW capture directory:
let captureRoot = '/path/to/new/captures';
let fs = await import('node:fs/promises');
let names = ['01-auth-burst', '02-denied-ports', '03-window-and-duplicates',
             '04-expectation-mismatch', '05-verification'];
// Run individually, inspecting AX state and each returned screenshot:
// await tab.goto('http://127.0.0.1:8777/viewer/' + name + '.html');
// await tab.getAXState();
// let shot = await tab.screenshot({fullPage:true});
// await fs.writeFile(captureRoot + '/' + name + '.jpg', shot, {flag:'wx'});
// await nodeRepl.emitImage(shot);
// Originals: Codex in-app browser; default 1280x720 viewport, no override.
// Save returned JPEG bytes directly: no crop, resize, composite or postprocessing.
