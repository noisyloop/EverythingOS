// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - File Operations Tool
// Read, write, list files (sensitive - requires approval)
// ═══════════════════════════════════════════════════════════════════════════════

import { Tool, ToolResult } from '../ToolTypes';
import * as fs from 'fs/promises';
import * as path from 'path';

// Sandbox directory - tools can only access files here
let sandboxDir = process.cwd();

export function setSandboxDirectory(dir: string): void {
  sandboxDir = path.resolve(dir);
}

function isPathSafe(filePath: string): boolean {
  const resolved = path.resolve(sandboxDir, filePath);
  // Use separator-aware check to prevent prefix confusion (e.g. /data vs /data-private)
  return resolved === sandboxDir || resolved.startsWith(sandboxDir + path.sep);
}

async function resolveSafePathAsync(filePath: string): Promise<string> {
  const resolved = path.resolve(sandboxDir, filePath);
  if (resolved !== sandboxDir && !resolved.startsWith(sandboxDir + path.sep)) {
    throw new Error('Path traversal attempt blocked');
  }

  // Resolve symlinks to their real path to prevent sandbox escape via symlinks
  try {
    const real = await fs.realpath(resolved);
    if (real !== sandboxDir && !real.startsWith(sandboxDir + path.sep)) {
      throw new Error('Path traversal attempt blocked (symlink escape)');
    }
    return real;
  } catch (err) {
    // File may not exist yet (e.g. for writes); validate the parent directory instead
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      const parentReal = await fs.realpath(path.dirname(resolved));
      if (parentReal !== sandboxDir && !parentReal.startsWith(sandboxDir + path.sep)) {
        throw new Error('Path traversal attempt blocked (symlink escape)');
      }
      return path.join(parentReal, path.basename(resolved));
    }
    throw err;
  }
}

function resolveSafePath(filePath: string): string {
  const resolved = path.resolve(sandboxDir, filePath);
  if (resolved !== sandboxDir && !resolved.startsWith(sandboxDir + path.sep)) {
    throw new Error('Path traversal attempt blocked');
  }
  return resolved;
}

export const fileReadTool: Tool = {
  name: 'file_read',
  version: '1.0.0',
  description: 'Read the contents of a file. Only works within the sandbox directory.',
  category: 'file',
  trustLevel: 'moderate',
  
  inputSchema: {
    type: 'object',
    properties: {
      path: {
        type: 'string',
        description: 'Path to the file (relative to sandbox)',
      },
      encoding: {
        type: 'string',
        description: 'File encoding (default: utf-8)',
        enum: ['utf-8', 'ascii', 'base64'],
      },
    },
    required: ['path'],
  },
  
  handler: async (input, context): Promise<ToolResult> => {
    const { path: filePath, encoding = 'utf-8' } = input as { path: string; encoding?: BufferEncoding };

    try {
      const safePath = await resolveSafePathAsync(filePath);
      const content = await fs.readFile(safePath, { encoding });
      
      context.log('info', `Read file: ${filePath}`);
      
      return {
        success: true,
        data: {
          path: filePath,
          content,
          size: content.length,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'File read failed',
      };
    }
  },
};

export const fileWriteTool: Tool = {
  name: 'file_write',
  version: '1.0.0',
  description: 'Write content to a file. Only works within the sandbox directory. Requires approval.',
  category: 'file',
  trustLevel: 'sensitive',
  requiresApproval: true,
  
  inputSchema: {
    type: 'object',
    properties: {
      path: {
        type: 'string',
        description: 'Path to the file (relative to sandbox)',
      },
      content: {
        type: 'string',
        description: 'Content to write',
      },
      append: {
        type: 'boolean',
        description: 'Append to file instead of overwriting (default: false)',
      },
    },
    required: ['path', 'content'],
  },
  
  handler: async (input, context): Promise<ToolResult> => {
    const { path: filePath, content, append = false } = input as {
      path: string;
      content: string;
      append?: boolean;
    };
    
    try {
      const safePath = await resolveSafePathAsync(filePath);

      // Ensure directory exists
      await fs.mkdir(path.dirname(safePath), { recursive: true });
      
      if (append) {
        await fs.appendFile(safePath, content, 'utf-8');
      } else {
        await fs.writeFile(safePath, content, 'utf-8');
      }
      
      context.log('info', `Wrote file: ${filePath} (${content.length} bytes)`);
      
      return {
        success: true,
        data: {
          path: filePath,
          bytesWritten: content.length,
          append,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'File write failed',
      };
    }
  },
};

export const fileListTool: Tool = {
  name: 'file_list',
  version: '1.0.0',
  description: 'List files in a directory. Only works within the sandbox directory.',
  category: 'file',
  trustLevel: 'safe',
  
  inputSchema: {
    type: 'object',
    properties: {
      path: {
        type: 'string',
        description: 'Directory path (relative to sandbox, default: current directory)',
      },
      recursive: {
        type: 'boolean',
        description: 'List recursively (default: false)',
      },
    },
  },
  
  handler: async (input, context): Promise<ToolResult> => {
    const { path: dirPath = '.', recursive = false } = input as {
      path?: string;
      recursive?: boolean;
    };
    
    try {
      const safePath = await resolveSafePathAsync(dirPath);
      
      async function listDir(dir: string, prefix = ''): Promise<string[]> {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        const files: string[] = [];
        
        for (const entry of entries) {
          const fullPath = path.join(prefix, entry.name);
          
          if (entry.isDirectory()) {
            files.push(fullPath + '/');
            if (recursive) {
              files.push(...await listDir(path.join(dir, entry.name), fullPath));
            }
          } else {
            files.push(fullPath);
          }
        }
        
        return files;
      }
      
      const files = await listDir(safePath);
      
      context.log('info', `Listed ${files.length} files in ${dirPath}`);
      
      return {
        success: true,
        data: {
          path: dirPath,
          files,
          count: files.length,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Directory listing failed',
      };
    }
  },
};

export const fileDeleteTool: Tool = {
  name: 'file_delete',
  version: '1.0.0',
  description: 'Delete a file. Only works within the sandbox directory. Requires approval.',
  category: 'file',
  trustLevel: 'dangerous',
  requiresApproval: true,
  
  inputSchema: {
    type: 'object',
    properties: {
      path: {
        type: 'string',
        description: 'Path to the file (relative to sandbox)',
      },
    },
    required: ['path'],
  },
  
  handler: async (input, context): Promise<ToolResult> => {
    const { path: filePath } = input as { path: string };
    
    try {
      const safePath = await resolveSafePathAsync(filePath);

      // Check it exists first
      await fs.access(safePath);

      // Delete
      await fs.unlink(safePath);
      
      context.log('info', `Deleted file: ${filePath}`);
      
      return {
        success: true,
        data: {
          path: filePath,
          deleted: true,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'File delete failed',
      };
    }
  },
};
