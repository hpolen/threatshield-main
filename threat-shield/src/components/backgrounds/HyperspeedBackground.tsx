import React, { useRef, useEffect } from "react";

const HyperspeedBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const particles: { x: number; y: number; z: number }[] = [];
  const numParticles = 250;

  // Initialize particles
  useEffect(() => {
    for (let i = 0; i < numParticles; i++) {
      particles.push({
        x: (Math.random() - 0.5) * 2,
        y: (Math.random() - 0.5) * 2,
        z: Math.random(),
      });
    }
  }, []);

  // Animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d")!;
    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener("resize", handleResize);

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      for (let p of particles) {
        p.z -= 0.01;
        if (p.z <= 0) p.z = 1;

        const k = 0.3 / p.z;
        const x = p.x * k * width + width / 2;
        const y = p.y * k * height + height / 2;

        ctx.beginPath();
        ctx.fillStyle = `rgba(0, 255, 255, ${1 - p.z})`;
        ctx.arc(x, y, (1 - p.z) * 3, 0, Math.PI * 2);
        ctx.fill();
      }

      requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 w-full h-full z-0 pointer-events-none"
    />
  );
};

export default HyperspeedBackground;
