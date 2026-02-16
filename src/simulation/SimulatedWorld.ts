// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Simulated World
// 2D environment for testing robot agents without hardware
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../core/event-bus/EventBus';

export interface Position {
  x: number;
  y: number;
}

export interface Obstacle {
  id: string;
  position: Position;
  radius: number;
  type: 'static' | 'dynamic';
}

export interface Zone {
  id: string;
  type: 'safe' | 'warning' | 'danger' | 'goal';
  bounds: {
    minX: number;
    maxX: number;
    minY: number;
    maxY: number;
  };
}

export interface WorldConfig {
  width: number;
  height: number;
  obstacles?: Obstacle[];
  zones?: Zone[];
}

export class SimulatedWorld {
  private width: number;
  private height: number;
  private obstacles: Map<string, Obstacle> = new Map();
  private zones: Map<string, Zone> = new Map();
  private entities: Map<string, Position> = new Map();

  constructor(config: WorldConfig) {
    this.width = config.width;
    this.height = config.height;

    if (config.obstacles) {
      for (const obs of config.obstacles) {
        this.obstacles.set(obs.id, obs);
      }
    }

    if (config.zones) {
      for (const zone of config.zones) {
        this.zones.set(zone.id, zone);
      }
    }

    this.zones.set('boundary-warning', {
      id: 'boundary-warning',
      type: 'warning',
      bounds: { minX: 1, maxX: this.width - 1, minY: 1, maxY: this.height - 1 },
    });

    eventBus.emit('world:created', {
      width: this.width,
      height: this.height,
      obstacles: this.obstacles.size,
      zones: this.zones.size,
    });
  }

  registerEntity(id: string, position: Position): void {
    this.entities.set(id, { ...position });
    eventBus.emit('world:entity:registered', { id, position });
  }

  updateEntityPosition(id: string, position: Position): {
    allowed: boolean;
    reason?: string;
    collision?: Obstacle;
    zone?: Zone;
  } {
    if (position.x < 0 || position.x > this.width ||
        position.y < 0 || position.y > this.height) {
      eventBus.emit('world:collision:boundary', { entityId: id, position });
      return { allowed: false, reason: 'out_of_bounds' };
    }

    for (const [obsId, obs] of this.obstacles) {
      const distance = this.distance(position, obs.position);
      if (distance < obs.radius) {
        eventBus.emit('world:collision:obstacle', { entityId: id, obstacleId: obsId, position });
        return { allowed: false, reason: 'obstacle_collision', collision: obs };
      }
    }

    this.entities.set(id, { ...position });

    const currentZone = this.getZoneAt(position);
    if (currentZone) {
      eventBus.emit('world:zone:entered', { entityId: id, zone: currentZone, position });
      
      if (currentZone.type === 'danger') {
        eventBus.emit('world:danger', { entityId: id, zone: currentZone, position });
      } else if (currentZone.type === 'goal') {
        eventBus.emit('world:goal:reached', { entityId: id, zone: currentZone, position });
      }
      
      return { allowed: true, zone: currentZone };
    }

    return { allowed: true };
  }

  getEntityPosition(id: string): Position | undefined {
    return this.entities.get(id);
  }

  addObstacle(obstacle: Obstacle): void {
    this.obstacles.set(obstacle.id, obstacle);
    eventBus.emit('world:obstacle:added', obstacle);
  }

  removeObstacle(id: string): void {
    this.obstacles.delete(id);
    eventBus.emit('world:obstacle:removed', { id });
  }

  getObstacles(): Obstacle[] {
    return Array.from(this.obstacles.values());
  }

  addZone(zone: Zone): void {
    this.zones.set(zone.id, zone);
    eventBus.emit('world:zone:added', zone);
  }

  getZoneAt(position: Position): Zone | undefined {
    for (const zone of this.zones.values()) {
      if (position.x >= zone.bounds.minX && position.x <= zone.bounds.maxX &&
          position.y >= zone.bounds.minY && position.y <= zone.bounds.maxY) {
        return zone;
      }
    }
    return undefined;
  }

  getZones(): Zone[] {
    return Array.from(this.zones.values());
  }

  isValidPosition(position: Position): boolean {
    if (position.x < 0 || position.x > this.width ||
        position.y < 0 || position.y > this.height) {
      return false;
    }

    for (const obs of this.obstacles.values()) {
      if (this.distance(position, obs.position) < obs.radius) {
        return false;
      }
    }

    return true;
  }

  distanceToNearestObstacle(position: Position): number {
    let minDistance = Infinity;
    
    for (const obs of this.obstacles.values()) {
      const dist = this.distance(position, obs.position) - obs.radius;
      if (dist < minDistance) {
        minDistance = dist;
      }
    }
    
    const boundaryDistances = [
      position.x,
      this.width - position.x,
      position.y,
      this.height - position.y,
    ];
    
    for (const dist of boundaryDistances) {
      if (dist < minDistance) {
        minDistance = dist;
      }
    }
    
    return minDistance;
  }

  private distance(a: Position, b: Position): number {
    return Math.sqrt((a.x - b.x) ** 2 + (a.y - b.y) ** 2);
  }

  getInfo(): { width: number; height: number; obstacles: number; zones: number; entities: number } {
    return {
      width: this.width,
      height: this.height,
      obstacles: this.obstacles.size,
      zones: this.zones.size,
      entities: this.entities.size,
    };
  }

  render(): string {
    const scale = 2;
    const cols = Math.floor(this.width * scale);
    const rows = Math.floor(this.height * scale);
    const grid: string[][] = [];

    for (let y = 0; y < rows; y++) {
      grid[y] = [];
      for (let x = 0; x < cols; x++) {
        grid[y][x] = '·';
      }
    }

    for (const obs of this.obstacles.values()) {
      const ox = Math.floor(obs.position.x * scale);
      const oy = Math.floor(obs.position.y * scale);
      if (ox >= 0 && ox < cols && oy >= 0 && oy < rows) {
        grid[rows - 1 - oy][ox] = '█';
      }
    }

    for (const [id, pos] of this.entities) {
      const ex = Math.floor(pos.x * scale);
      const ey = Math.floor(pos.y * scale);
      if (ex >= 0 && ex < cols && ey >= 0 && ey < rows) {
        grid[rows - 1 - ey][ex] = '◉';
      }
    }

    const border = '─'.repeat(cols + 2);
    let output = `┌${border}┐\n`;
    for (const row of grid) {
      output += `│ ${row.join('')} │\n`;
    }
    output += `└${border}┘`;

    return output;
  }
}

export const createDefaultWorld = (): SimulatedWorld => {
  return new SimulatedWorld({
    width: 10,
    height: 10,
    obstacles: [
      { id: 'obs-1', position: { x: 3, y: 3 }, radius: 0.5, type: 'static' },
      { id: 'obs-2', position: { x: 7, y: 5 }, radius: 0.8, type: 'static' },
      { id: 'obs-3', position: { x: 5, y: 8 }, radius: 0.3, type: 'static' },
    ],
    zones: [
      { id: 'goal', type: 'goal', bounds: { minX: 8, maxX: 10, minY: 8, maxY: 10 } },
      { id: 'danger', type: 'danger', bounds: { minX: 4, maxX: 6, minY: 4, maxY: 6 } },
    ],
  });
};
