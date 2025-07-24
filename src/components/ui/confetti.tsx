'use client';

import { useEffect, useRef, useState } from 'react';

interface ConfettiProps {
  active?: boolean;
  config?: {
    angle?: number;
    spread?: number;
    startVelocity?: number;
    elementCount?: number;
    dragFriction?: number;
    duration?: number;
    stagger?: number;
    width?: string;
    height?: string;
    perspective?: string;
    colors?: string[];
  };
}

interface ConfettiElement {
  element: HTMLDivElement;
  x: number;
  y: number;
  z: number;
  vx: number;
  vy: number;
  vz: number;
  rotation: number;
  rotationSpeed: number;
  color: string;
}

export function Confetti({ active = false, config = {} }: ConfettiProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const elementsRef = useRef<ConfettiElement[]>([]);
  const animationRef = useRef<number | null>(null);

  const defaultConfig = {
    angle: 90,
    spread: 45,
    startVelocity: 45,
    elementCount: 50,
    dragFriction: 0.1,
    duration: 3000,
    stagger: 3,
    width: '10px',
    height: '10px',
    perspective: '500px',
    colors: ['#f43f5e', '#ec4899', '#8b5cf6', '#3b82f6', '#06b6d4', '#10b981', '#f59e0b', '#ef4444']
  };

  const finalConfig = { ...defaultConfig, ...config };

  useEffect(() => {
    if (!active || !containerRef.current) return;

    const container = containerRef.current;
    const elements: ConfettiElement[] = [];

    // Clear any existing elements
    container.innerHTML = '';
    elementsRef.current = [];

    // Create confetti elements
    for (let i = 0; i < finalConfig.elementCount; i++) {
      const element = document.createElement('div');
      element.style.position = 'absolute';
      element.style.width = finalConfig.width;
      element.style.height = finalConfig.height;
      element.style.backgroundColor = finalConfig.colors[Math.floor(Math.random() * finalConfig.colors.length)];
      element.style.borderRadius = Math.random() > 0.5 ? '50%' : '0';
      element.style.pointerEvents = 'none';
      element.style.zIndex = '9999';

      // Random starting position at the top
      const x = Math.random() * window.innerWidth;
      const y = -10;
      const z = Math.random() * 100;

      // Calculate velocity based on angle and spread
      const angleRad = (finalConfig.angle * Math.PI) / 180;
      const spreadRad = (finalConfig.spread * Math.PI) / 180;
      const randomAngle = angleRad + (Math.random() - 0.5) * spreadRad;

      const vx = Math.cos(randomAngle) * finalConfig.startVelocity * (0.5 + Math.random() * 0.5);
      const vy = Math.sin(randomAngle) * finalConfig.startVelocity * (0.5 + Math.random() * 0.5);
      const vz = (Math.random() - 0.5) * 20;

      const confettiElement: ConfettiElement = {
        element,
        x,
        y,
        z,
        vx,
        vy: -Math.abs(vy), // Make sure it goes up initially
        vz,
        rotation: Math.random() * 360,
        rotationSpeed: (Math.random() - 0.5) * 10,
        color: element.style.backgroundColor
      };

      elements.push(confettiElement);
      container.appendChild(element);

      // Stagger the animation start
      setTimeout(() => {
        if (elementsRef.current.includes(confettiElement)) {
          animateElement(confettiElement);
        }
      }, i * finalConfig.stagger);
    }

    elementsRef.current = elements;

    // Clean up after duration
    const cleanup = setTimeout(() => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
      container.innerHTML = '';
      elementsRef.current = [];
    }, finalConfig.duration);

    return () => {
      clearTimeout(cleanup);
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
      container.innerHTML = '';
      elementsRef.current = [];
    };
  }, [active, finalConfig]);

  const animateElement = (confettiElement: ConfettiElement) => {
    const animate = () => {
      // Update physics
      confettiElement.vy += 0.5; // Gravity
      confettiElement.vx *= (1 - finalConfig.dragFriction);
      confettiElement.vy *= (1 - finalConfig.dragFriction);
      confettiElement.vz *= (1 - finalConfig.dragFriction);

      confettiElement.x += confettiElement.vx;
      confettiElement.y += confettiElement.vy;
      confettiElement.z += confettiElement.vz;
      confettiElement.rotation += confettiElement.rotationSpeed;

      // Update element position and rotation
      const scale = Math.max(0.1, 1 + confettiElement.z / 100);
      confettiElement.element.style.left = `${confettiElement.x}px`;
      confettiElement.element.style.top = `${confettiElement.y}px`;
      confettiElement.element.style.transform = `rotate(${confettiElement.rotation}deg) scale(${scale})`;
      confettiElement.element.style.opacity = Math.max(0, 1 - confettiElement.y / window.innerHeight).toString();

      // Continue animation if element is still visible
      if (confettiElement.y < window.innerHeight + 100 && elementsRef.current.includes(confettiElement)) {
        animationRef.current = requestAnimationFrame(animate);
      }
    };

    animate();
  };

  if (!active) return null;

  return (
    <div
      ref={containerRef}
      className="fixed inset-0 pointer-events-none z-50"
      style={{ perspective: finalConfig.perspective }}
    />
  );
}

// Hook for easy confetti triggering
export function useConfetti() {
  const trigger = (config?: ConfettiProps['config']) => {
    const event = new CustomEvent('triggerConfetti', { detail: config });
    window.dispatchEvent(event);
  };

  return { trigger };
}

// Global confetti provider component
export function ConfettiProvider({ children }: { children: React.ReactNode }) {
  const [active, setActive] = useState(false);
  const [config, setConfig] = useState({});

  useEffect(() => {
    const handleTrigger = (event: CustomEvent) => {
      setConfig(event.detail || {});
      setActive(true);
      
      // Auto-disable after animation
      setTimeout(() => setActive(false), 3000);
    };

    window.addEventListener('triggerConfetti', handleTrigger as EventListener);
    return () => window.removeEventListener('triggerConfetti', handleTrigger as EventListener);
  }, []);

  return (
    <>
      {children}
      <Confetti active={active} config={config} />
    </>
  );
}
