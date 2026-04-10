import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls';
import axios from 'axios';

interface AttackEvent {
  id: number;
  timestamp: string;
  attack_type: string;
  source_ip: string;
  target_ip: string;
  target_port: number;
  user_agent: string;
  status: string;
  request_method: string;
  request_path: string;
  request_params: Record<string, string>;
  response_code: number;
  severity: string;
  details: Record<string, string>;
}

const ThreeDScreen: React.FC = () => {
  const containerRef = useRef<HTMLDivElement>(null);
  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const controlsRef = useRef<OrbitControls | null>(null);
  const attackPointsRef = useRef<THREE.Points | null>(null);
  const networkLinesRef = useRef<THREE.LineSegments | null>(null);
  const animationIdRef = useRef<number>();
  const attackDataRef = useRef<AttackEvent[]>([]);
  const timeRef = useRef<number>(0);

  // 初始化Three.js场景
  useEffect(() => {
    if (!containerRef.current) return;

    // 创建场景
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0a1a);
    sceneRef.current = scene;

    // 创建相机
    const camera = new THREE.PerspectiveCamera(
      75,
      containerRef.current.clientWidth / containerRef.current.clientHeight,
      0.1,
      1000
    );
    camera.position.z = 50;
    cameraRef.current = camera;

    // 创建渲染器
    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(containerRef.current.clientWidth, containerRef.current.clientHeight);
    containerRef.current.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // 添加轨道控制器
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controlsRef.current = controls;

    // 添加光源
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
    scene.add(ambientLight);

    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(1, 1, 1);
    scene.add(directionalLight);

    // 创建地球模型
    createEarth(scene);

    // 创建攻击点和网络线
    createAttackPoints(scene);
    createNetworkLines(scene);

    // 动画循环
    const animate = () => {
      animationIdRef.current = requestAnimationFrame(animate);
      timeRef.current += 0.01;

      // 更新控制器
      controls.update();

      // 更新攻击点动画
      updateAttackPoints();

      // 更新网络线动画
      updateNetworkLines();

      // 渲染场景
      renderer.render(scene, camera);
    };

    animate();

    // 清理函数
    return () => {
      if (animationIdRef.current) {
        cancelAnimationFrame(animationIdRef.current);
      }
      if (containerRef.current && renderer.domElement) {
        containerRef.current.removeChild(renderer.domElement);
      }
    };
  }, []);

  // 定期获取攻击数据
  useEffect(() => {
    const fetchAttackData = async () => {
      try {
        const response = await axios.get('/api/attack-events', { params: { limit: 100 } });
        if (Array.isArray(response.data)) {
          attackDataRef.current = response.data;
          updateAttackPoints();
          updateNetworkLines();
        }
      } catch (error) {
        console.error('获取攻击数据失败:', error);
      }
    };

    // 初始获取
    fetchAttackData();

    // 每5秒获取一次数据
    const interval = setInterval(fetchAttackData, 5000);

    return () => clearInterval(interval);
  }, []);

  // 处理窗口大小变化
  useEffect(() => {
    const handleResize = () => {
      if (!containerRef.current || !cameraRef.current || !rendererRef.current) return;

      const width = containerRef.current.clientWidth;
      const height = containerRef.current.clientHeight;

      cameraRef.current.aspect = width / height;
      cameraRef.current.updateProjectionMatrix();
      rendererRef.current.setSize(width, height);
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // 创建地球模型
  const createEarth = (scene: THREE.Scene) => {
    // 创建地球几何体
    const geometry = new THREE.SphereGeometry(10, 64, 64);

    // 创建地球材质
    const material = new THREE.MeshPhongMaterial({
      color: 0x1a237e,
      specular: 0x333333,
      shininess: 10,
      transparent: true,
      opacity: 0.8
    });

    // 创建地球网格
    const earth = new THREE.Mesh(geometry, material);
    scene.add(earth);

    // 创建地球大气层
    const atmosphereGeometry = new THREE.SphereGeometry(10.2, 64, 64);
    const atmosphereMaterial = new THREE.MeshBasicMaterial({
      color: 0x42a5f5,
      transparent: true,
      opacity: 0.3
    });
    const atmosphere = new THREE.Mesh(atmosphereGeometry, atmosphereMaterial);
    scene.add(atmosphere);

    // 创建地球自转动画
    const animateEarth = () => {
      earth.rotation.y += 0.001;
      atmosphere.rotation.y += 0.001;
      requestAnimationFrame(animateEarth);
    };
    animateEarth();
  };

  // 创建攻击点
  const createAttackPoints = (scene: THREE.Scene) => {
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(1000 * 3); // 最多1000个攻击点
    const colors = new Float32Array(1000 * 3);

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
      size: 0.5,
      vertexColors: true,
      transparent: true,
      opacity: 0.8
    });

    const points = new THREE.Points(geometry, material);
    scene.add(points);
    attackPointsRef.current = points;
  };

  // 更新攻击点
  const updateAttackPoints = () => {
    if (!attackPointsRef.current || !attackDataRef.current) return;

    const points = attackPointsRef.current;
    const geometry = points.geometry as THREE.BufferGeometry;
    const positions = geometry.attributes.position.array as Float32Array;
    const colors = geometry.attributes.color.array as Float32Array;

    const attacks = attackDataRef.current.slice(0, 333); // 最多333个攻击点

    for (let i = 0; i < attacks.length; i++) {
      const attack = attacks[i];
      // 生成随机位置（模拟全球攻击）
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      const radius = 10 + Math.random() * 5;

      const x = radius * Math.sin(phi) * Math.cos(theta);
      const y = radius * Math.sin(phi) * Math.sin(theta);
      const z = radius * Math.cos(phi);

      positions[i * 3] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;

      // 根据攻击类型设置颜色
      let color;
      switch (attack.attack_type) {
        case 'SQL Injection':
          color = new THREE.Color(0xff4444); // 红色
          break;
        case 'XSS':
          color = new THREE.Color(0xffbb33); // 黄色
          break;
        case 'DDoS':
          color = new THREE.Color(0x33b5e5); // 蓝色
          break;
        case 'Brute Force':
          color = new THREE.Color(0x99cc00); // 绿色
          break;
        default:
          color = new THREE.Color(0xaa66cc); // 紫色
      }

      colors[i * 3] = color.r;
      colors[i * 3 + 1] = color.g;
      colors[i * 3 + 2] = color.b;
    }

    // 清空剩余的点
    for (let i = attacks.length; i < 333; i++) {
      positions[i * 3] = 0;
      positions[i * 3 + 1] = 0;
      positions[i * 3 + 2] = 0;
      colors[i * 3] = 0;
      colors[i * 3 + 1] = 0;
      colors[i * 3 + 2] = 0;
    }

    geometry.attributes.position.needsUpdate = true;
    geometry.attributes.color.needsUpdate = true;
  };

  // 创建网络线
  const createNetworkLines = (scene: THREE.Scene) => {
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(2000 * 3); // 最多1000条线

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const material = new THREE.LineBasicMaterial({
      color: 0x42a5f5,
      transparent: true,
      opacity: 0.3
    });

    const lines = new THREE.LineSegments(geometry, material);
    scene.add(lines);
    networkLinesRef.current = lines;
  };

  // 更新网络线
  const updateNetworkLines = () => {
    if (!networkLinesRef.current || !attackDataRef.current) return;

    const lines = networkLinesRef.current;
    const geometry = lines.geometry as THREE.BufferGeometry;
    const positions = geometry.attributes.position.array as Float32Array;

    const attacks = attackDataRef.current.slice(0, 500); // 最多500条线

    for (let i = 0; i < attacks.length; i++) {
      // 生成随机起点和终点
      const startTheta = Math.random() * Math.PI * 2;
      const startPhi = Math.acos(2 * Math.random() - 1);
      const startRadius = 10 + Math.random() * 2;

      const endTheta = Math.random() * Math.PI * 2;
      const endPhi = Math.acos(2 * Math.random() - 1);
      const endRadius = 10 + Math.random() * 2;

      const startX = startRadius * Math.sin(startPhi) * Math.cos(startTheta);
      const startY = startRadius * Math.sin(startPhi) * Math.sin(startTheta);
      const startZ = startRadius * Math.cos(startPhi);

      const endX = endRadius * Math.sin(endPhi) * Math.cos(endTheta);
      const endY = endRadius * Math.sin(endPhi) * Math.sin(endTheta);
      const endZ = endRadius * Math.cos(endPhi);

      positions[i * 6] = startX;
      positions[i * 6 + 1] = startY;
      positions[i * 6 + 2] = startZ;
      positions[i * 6 + 3] = endX;
      positions[i * 6 + 4] = endY;
      positions[i * 6 + 5] = endZ;
    }

    // 清空剩余的线
    for (let i = attacks.length; i < 500; i++) {
      positions[i * 6] = 0;
      positions[i * 6 + 1] = 0;
      positions[i * 6 + 2] = 0;
      positions[i * 6 + 3] = 0;
      positions[i * 6 + 4] = 0;
      positions[i * 6 + 5] = 0;
    }

    geometry.attributes.position.needsUpdate = true;
  };

  return (
    <div className="p-6 bg-gray-900 min-h-screen">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-3xl font-bold mb-6 text-white">3D安全态势大屏</h1>
        
        <div 
          ref={containerRef} 
          style={{ 
            width: '100%', 
            height: '80vh', 
            borderRadius: '8px', 
            overflow: 'hidden',
            boxShadow: '0 0 20px rgba(0, 184, 148, 0.3)'
          }} 
        />

        <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-lg font-medium text-white mb-2">攻击统计</h3>
            <p className="text-gray-400">实时显示全球网络攻击态势</p>
            <p className="text-gray-400 mt-2">攻击类型: SQL注入、XSS、DDoS、暴力破解等</p>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-lg font-medium text-white mb-2">交互说明</h3>
            <p className="text-gray-400">鼠标拖动: 旋转视角</p>
            <p className="text-gray-400">滚轮: 缩放</p>
            <p className="text-gray-400">Shift+拖动: 平移</p>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-lg font-medium text-white mb-2">数据来源</h3>
            <p className="text-gray-400">攻击事件: /api/attack-events</p>
            <p className="text-gray-400">数据更新频率: 每5秒</p>
            <p className="text-gray-400">最大显示: 1000个攻击点</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreeDScreen;