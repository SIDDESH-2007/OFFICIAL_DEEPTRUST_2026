import fs from 'fs';
import readline from 'readline';

async function restore() {
  const logPath = `C:\\Users\\SIDDESHWAR BS\\.gemini\\antigravity-ide\\brain\\2e2ddc15-087c-4be4-8432-4bb860a70120\\.system_generated\\logs\\transcript_full.jsonl`;
  
  const fileStream = fs.createReadStream(logPath);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });

  const files = {};

  for await (const line of rl) {
    try {
      const entry = JSON.parse(line);
      if (entry.type === 'VIEW_FILE' && entry.content) {
         const output = entry.content;
         if (output.includes('The following code has been modified to include a line number')) {
            const matchPath = output.match(/File Path: `file:\/\/\/(.+?)`/);
            if (matchPath) {
                let decodedPath = decodeURIComponent(matchPath[1]);
                if (!files[decodedPath]) {
                    const lines = output.split('\n');
                    let codeContent = [];
                    for (const l of lines) {
                        const codeMatch = l.match(/^\d+:(.*)/);
                        if (codeMatch) {
                            let c = codeMatch[1];
                            if (c.startsWith(' ')) c = c.substring(1);
                            codeContent.push(c);
                        }
                    }
                    files[decodedPath] = codeContent.join('\n');
                }
            }
         }
      }
    } catch (e) {}
  }
  
  for (const [path, content] of Object.entries(files)) {
      if (path.toLowerCase().includes('deeptrust project 2026/deeptrust/deeeptrust.02/deeptrust-mvp')) {
          let windowsPath = path.replace(/\//g, '\\');
          windowsPath = windowsPath.replace(/^d:/i, 'd:');
          console.log(`Restoring ${windowsPath}...`);
          try {
              fs.writeFileSync(windowsPath, content, 'utf8');
              console.log(`Restored ${windowsPath}`);
          } catch (err) {
              console.error(`Failed to write ${windowsPath}:`, err);
          }
      }
  }
}

restore();
