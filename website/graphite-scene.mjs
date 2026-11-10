import * as THREE from './vendor/three-0.180.0/three.module.min.js';

export const Engine = THREE;

/** Build only local geometry: no loaders, textures, remote assets, or user data. */
export function createGraphiteScene() {
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(36, 1, .1, 30);
  camera.position.set(0, 0, 9.6);
  const rig = new THREE.Group();
  scene.add(rig);

  const faceMaterial = new THREE.MeshStandardMaterial({ color: 0x353535, metalness: .55, roughness: .53 });
  const rimMaterial = new THREE.MeshStandardMaterial({ color: 0xaaaaaa, metalness: .8, roughness: .32 });
  const orbitMaterial = new THREE.MeshStandardMaterial({ color: 0x747474, metalness: .65, roughness: .45 });
  const markerMaterial = new THREE.MeshStandardMaterial({ color: 0xe8e8e8, emissive: 0x333333, metalness: .3, roughness: .4 });

  const plate = new THREE.Mesh(new THREE.CylinderGeometry(2.21, 2.21, .14, 96), faceMaterial);
  plate.rotation.x = Math.PI / 2;
  rig.add(plate);
  const rim = new THREE.Mesh(new THREE.TorusGeometry(2.21, .045, 12, 128), rimMaterial);
  rim.position.z = .055;
  rig.add(rim);

  const orbitA = new THREE.Group();
  const orbitB = new THREE.Group();
  orbitA.add(new THREE.Mesh(new THREE.TorusGeometry(2.53, .014, 8, 128), orbitMaterial));
  orbitB.add(new THREE.Mesh(new THREE.TorusGeometry(2.82, .009, 8, 128), orbitMaterial));
  rig.add(orbitA, orbitB);
  const markers = new THREE.InstancedMesh(new THREE.SphereGeometry(.032, 8, 6), markerMaterial, 6);
  markers.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
  orbitA.add(markers);

  scene.add(new THREE.AmbientLight(0xffffff, 1.5));
  const key = new THREE.DirectionalLight(0xffffff, 3.5);
  key.position.set(-3.5, 4.5, 5);
  const fill = new THREE.DirectionalLight(0xffffff, 1.6);
  fill.position.set(4, -1, 3);
  const edge = new THREE.DirectionalLight(0xffffff, 2);
  edge.position.set(1, 4, -3);
  scene.add(key, fill, edge);

  const model = {
    scene, camera, rig, orbitA, orbitB, markers, key,
    markerTransform: new THREE.Object3D(),
    state: { x: 0, y: 0, pulse: 0, lastPhase: 'arriving', disposed: false }
  };
  updateGraphiteScene(model, { time: 0, delta: 0, progress: 0, pointer: { x: 0, y: 0 }, phase: 'arriving' });
  return model;
}

export function updateGraphiteScene(model, { time, delta, progress, pointer, phase }) {
  if (model.state.disposed) return;
  const state = model.state;
  const blend = 1 - Math.exp(-Math.max(0, delta) * 7);
  state.x += (pointer.x - state.x) * blend;
  state.y += (pointer.y - state.y) * blend;
  if (phase === 'danger' && state.lastPhase !== 'danger') state.pulse = 1;
  state.lastPhase = phase;
  state.pulse *= Math.exp(-Math.max(0, delta) * 4);
  model.rig.rotation.set(
    -.08 - progress * .55 + state.y * .12,
    .12 + Math.sin(time * .28) * .055 + state.x * .15,
    Math.sin(time * 42) * state.pulse * .014
  );
  model.rig.position.y = Math.sin(time * .5) * .025 - progress * .1;
  model.orbitA.rotation.set(.28, -.12, .18 + time * .035);
  model.orbitB.rotation.set(-.12, .3, -.24 - time * .025);
  model.key.intensity = 3.5 + state.pulse * 1.2;
  const speed = phase === 'blocked' ? .1 : .25;
  for (let index = 0; index < model.markers.count; index++) {
    const angle = time * speed + index * Math.PI / 3;
    model.markerTransform.position.set(Math.cos(angle) * 2.53, Math.sin(angle) * 2.53, .025);
    model.markerTransform.updateMatrix();
    model.markers.setMatrixAt(index, model.markerTransform.matrix);
  }
  model.markers.instanceMatrix.needsUpdate = true;
}

export function disposeGraphiteScene(model) {
  if (model.state.disposed) return;
  model.state.disposed = true;
  const geometries = new Set();
  const materials = new Set();
  model.scene.traverse(object => {
    if (object.geometry) geometries.add(object.geometry);
    for (const material of Array.isArray(object.material) ? object.material : [object.material]) {
      if (material) materials.add(material);
    }
    if (object.isInstancedMesh) object.dispose();
  });
  geometries.forEach(geometry => geometry.dispose());
  materials.forEach(material => material.dispose());
  model.scene.clear();
}
