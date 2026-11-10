import {
  DataTexture, LinearFilter, Mesh, NoColorSpace, OrthographicCamera,
  PlaneGeometry, RGBAFormat, Scene, ShaderMaterial, SRGBColorSpace,
  UnsignedByteType, Vector2, WebGLRenderer
} from './vendor/three-0.180.0/three.module.min.js';

// Exact squared Euclidean distance transform, O(width * height).
function distanceTransform(field, width, height) {
  const size = Math.max(width, height);
  const values = new Float64Array(size);
  const result = new Float64Array(size);
  const sites = new Int32Array(size);
  const bounds = new Float64Array(size + 1);
  function line(length) {
    let last = 0;
    sites[0] = 0;
    bounds[0] = -Infinity;
    bounds[1] = Infinity;
    for (let point = 1; point < length; point++) {
      let split;
      do {
        const previous = sites[last];
        split = ((values[point] + point * point) - (values[previous] + previous * previous)) / (2 * (point - previous));
        if (split > bounds[last]) break;
        last--;
      } while (last >= 0);
      last++;
      sites[last] = point;
      bounds[last] = split;
      bounds[last + 1] = Infinity;
    }
    last = 0;
    for (let point = 0; point < length; point++) {
      while (bounds[last + 1] < point) last++;
      const delta = point - sites[last];
      result[point] = delta * delta + values[sites[last]];
    }
  }
  for (let x = 0; x < width; x++) {
    for (let y = 0; y < height; y++) values[y] = field[y * width + x];
    line(height);
    for (let y = 0; y < height; y++) field[y * width + x] = result[y];
  }
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) values[x] = field[y * width + x];
    line(width);
    for (let x = 0; x < width; x++) field[y * width + x] = result[x];
  }
}

export function buildDistanceField(alpha, width, height, range = 40, bevel = range * .85) {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1 ||
      alpha.length !== width * height || !(range > 0) || !(bevel > 0)) throw new Error('Invalid text mask');
  const inside = new Float64Array(alpha.length);
  const outside = new Float64Array(alpha.length);
  for (let index = 0; index < alpha.length; index++) {
    const coverage = alpha[index] / 255;
    inside[index] = coverage === 1 ? 1e12 : Math.max(0, coverage - .5) ** 2;
    outside[index] = coverage === 0 ? 1e12 : Math.max(0, .5 - coverage) ** 2;
  }
  distanceTransform(inside, width, height);
  distanceTransform(outside, width, height);
  const surface = new Float32Array(alpha.length);
  for (let index = 0; index < alpha.length; index++) {
    surface[index] = alpha[index] / 255 * bevel * 1.9;
  }
  // Filter the surface before deriving normals. This removes raster-edge grain
  // and softens the medial ridges into a rounded, continuous glass profile.
  const temporary = new Float32Array(surface.length);
  const radius = Math.max(2, Math.round(bevel * .23));
  const divisor = radius * 2 + 1;
  // Three separable box passes approximate a Gaussian without a wide per-pixel
  // kernel. The smooth height field avoids faceted corners and center creases.
  for (let pass = 0; pass < 3; pass++) {
    for (let y = 0; y < height; y++) {
      let value = 0;
      for (let tap = -radius; tap <= radius; tap++) value += surface[y * width + Math.max(0, Math.min(width - 1, tap))];
      for (let x = 0; x < width; x++) {
        temporary[y * width + x] = value / divisor;
        value += surface[y * width + Math.min(width - 1, x + radius + 1)] - surface[y * width + Math.max(0, x - radius)];
      }
    }
    for (let x = 0; x < width; x++) {
      let value = 0;
      for (let tap = -radius; tap <= radius; tap++) value += temporary[Math.max(0, Math.min(height - 1, tap)) * width + x];
      for (let y = 0; y < height; y++) {
        surface[y * width + x] = value / divisor;
        value += temporary[Math.min(height - 1, y + radius + 1) * width + x] - temporary[Math.max(0, y - radius) * width + x];
      }
    }
  }
  const pixels = new Uint8Array(width * height * 4);
  for (let index = 0; index < alpha.length; index++) {
    const distance = Math.sqrt(inside[index]) - Math.sqrt(outside[index]);
    const value = Math.round(255 * Math.max(0, Math.min(1, .5 + distance / (range * 2))));
    const x = index % width, y = Math.floor(index / width);
    const dx = (surface[y * width + Math.min(width - 1, x + 1)] - surface[y * width + Math.max(0, x - 1)]) * .5;
    const dy = (surface[Math.min(height - 1, y + 1) * width + x] - surface[Math.max(0, y - 1) * width + x]) * .5;
    const length = Math.hypot(dx, dy, 1);
    pixels[index * 4] = value;
    pixels[index * 4 + 1] = Math.round(255 * (.5 - .5 * dx / length));
    pixels[index * 4 + 2] = Math.round(255 * (.5 + .5 * dy / length));
    pixels[index * 4 + 3] = 255;
  }
  return pixels;
}

export const vertexShader = /* glsl */`
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = vec4(position.xy, 0.0, 1.0);
  }
`;

export const fragmentShader = /* glsl */`
  uniform sampler2D uShape;
  uniform vec2 uTexel;
  uniform float uRange;
  uniform float uBevel;
  uniform float uTime;
  uniform float uDock;
  varying vec2 vUv;

  float shape(vec2 uv) { return (texture2D(uShape, uv).r - .5) * (2.0 * uRange); }
  float softbox(float value, float center, float width) {
    float delta = (value - center) / width;
    return exp(-delta * delta);
  }
  vec3 studio(vec3 ray, float time) {
    float angle = atan(ray.x, ray.z);
    float height = ray.y;
    // Wide studio panels bend continuously over the curved letter surfaces.
    float key = softbox(angle + .28 * sin(height * 3.2 + time * .65) + (vUv.x - .5) * 1.55,
      -.85 + time * .30, .18);
    float fill = softbox(angle - .18 * sin(height * 4.0 - time * .45), 1.45, .38);
    float rim = softbox(height + .12 * sin(angle * 3.0 + time * .6), .64, .16);
    float floorLight = softbox(height, -.76, .12);
    return vec3(.018, .020, .025) + key * vec3(3.4, 3.5, 3.6)
      + fill * vec3(.75, .8, .86) + rim * vec3(1.6, 1.65, 1.7)
      + floorLight * vec3(.38, .4, .44);
  }
  vec3 aces(vec3 color) {
    return clamp((color * (2.51 * color + .03)) / (color * (2.43 * color + .59) + .14), 0.0, 1.0);
  }
  void main() {
    vec2 uv = vec2(vUv.x, 1.0 - vUv.y);
    float liquid = 1.0 - uDock;
    // Subpixel surface flow, with a stable, readable silhouette.
    uv += liquid * uTexel * .5 * vec2(
      sin(uv.y * 9.0 + uTime * .8), cos(uv.x * 7.0 - uTime * .65));
    float distance = shape(uv);
    float aa = max(fwidth(distance) * .7, .22);
    float alpha = smoothstep(-aa, aa, distance);
    if (alpha < .001) discard;

    float edge = clamp(distance / uBevel, 0.0, 1.0);
    float curve = sqrt(max(.008, 1.0 - (1.0 - edge) * (1.0 - edge)));
    vec2 rounded = texture2D(uShape, uv).gb * 2.0 - 1.0;
    vec2 flow = .16 * vec2(
      sin(uv.x * 5.7 + uv.y * 3.6 + uTime * .6),
      cos(uv.x * 4.2 - uv.y * 5.8 - uTime * .52));
    vec3 normal = normalize(vec3((rounded + flow * .55) * liquid,
      mix(1.0, sqrt(max(.02, 1.0 - dot(rounded, rounded))), liquid)));
    vec3 view = normalize(vec3((vUv - .5) * vec2(.23, .13), 1.0));
    float facing = max(dot(normal, view), 0.0);
    float fresnel = .045 + .955 * pow(1.0 - facing, 4.0);
    vec3 reflected = studio(reflect(-view, normal), uTime);
    // Slightly different refractive indices give a restrained glass dispersion.
    vec3 rr = refract(-view, normal, 1.0 / 1.47);
    vec3 rg = refract(-view, normal, 1.0 / 1.485);
    vec3 rb = refract(-view, normal, 1.0 / 1.50);
    vec3 red = studio(vec3(rr.xy, abs(rr.z)), uTime + .7);
    vec3 green = studio(vec3(rg.xy, abs(rg.z)), uTime + .7);
    vec3 blue = studio(vec3(rb.xy, abs(rb.z)), uTime + .7);
    vec3 transmitted = vec3(red.r, green.g, blue.b);
    float absorption = exp(-.6 * curve);
    float rim = pow(1.0 - edge, 2.0);
    vec3 light = reflected * (.22 + fresnel * 1.15)
      + transmitted * absorption * .32 * (1.0 - fresnel)
      + vec3(.006, .007, .009) * curve + vec3(.012, .014, .018) * rim;
    vec3 color = mix(aces(light * 1.35), vec3(.93), uDock);
    gl_FragColor = vec4(color, alpha);
    #include <colorspace_fragment>
  }
`;

function createShapeTexture(word) {
  const rect = word.getBoundingClientRect();
  const style = getComputedStyle(word);
  const fontSize = parseFloat(style.fontSize);
  if (!(fontSize > 0) || !rect.width || !rect.height) throw new Error('Wordmark has no drawable size');
  const density = Math.min(2, 320 / fontSize);
  const padding = Math.ceil(fontSize * .08);
  const width = Math.ceil((rect.width + padding * 2) * density);
  const height = Math.ceil((rect.height + padding * 2) * density);
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext('2d', { willReadFrequently:true });
  if (!context) throw new Error('Text rasterization unavailable');
  const rasterSize = fontSize * density;
  context.font = `${style.fontWeight} ${rasterSize}px ${style.fontFamily}`;
  context.fillStyle = '#fff';
  context.textBaseline = 'alphabetic';
  const text = word.dataset.word;
  const metrics = context.measureText(text);
  const ascent = metrics.fontBoundingBoxAscent ?? rasterSize * .9;
  const descent = metrics.fontBoundingBoxDescent ?? rasterSize * .22;
  const baseline = padding * density + (rect.height * density - ascent - descent) / 2 + ascent;
  const tracking = parseFloat(style.letterSpacing) * density || 0;
  if ('letterSpacing' in context) {
    context.letterSpacing = `${tracking}px`;
    context.fillText(text, padding * density, baseline);
  } else {
    let x = padding * density;
    for (const letter of text) {
      context.fillText(letter, x, baseline);
      x += context.measureText(letter).width + tracking;
    }
  }
  const rgba = context.getImageData(0, 0, width, height).data;
  const alpha = new Uint8Array(width * height);
  for (let index = 0; index < alpha.length; index++) alpha[index] = rgba[index * 4 + 3];
  const range = Math.max(20, rasterSize * .13);
  const bevel = rasterSize * .11;
  const texture = new DataTexture(buildDistanceField(alpha, width, height, range, bevel), width, height, RGBAFormat, UnsignedByteType);
  texture.minFilter = texture.magFilter = LinearFilter;
  texture.generateMipmaps = false;
  texture.colorSpace = NoColorSpace;
  texture.needsUpdate = true;
  return { texture, width, height, padding, cssWidth:rect.width + padding * 2,
    cssHeight:rect.height + padding * 2, range, bevel };
}

export function createLiquidLogo(word, { onError = () => {}, rendererFactory = options => new WebGLRenderer(options),
  now = () => performance.now(), requestFrame = requestAnimationFrame, cancelFrame = cancelAnimationFrame } = {}) {
  let renderer, shape, geometry, material, frame;
  let disposed = false;
  let dockStart = null;
  const started = now();
  const canvas = document.createElement('canvas');
  canvas.className = 'intro-glass-canvas';
  canvas.setAttribute('aria-hidden', 'true');
  function dispose() {
    if (disposed) return;
    disposed = true;
    if (frame !== undefined) cancelFrame(frame);
    canvas.removeEventListener('webglcontextlost', contextLost);
    geometry?.dispose();
    material?.dispose();
    shape?.texture.dispose();
    renderer?.dispose();
    renderer?.forceContextLoss();
    canvas.remove();
    word.classList.remove('has-glass');
  }
  function contextLost(event) {
    event.preventDefault();
    dispose();
    onError();
  }
  try {
    shape = createShapeTexture(word);
    renderer = rendererFactory({ canvas, alpha:true, antialias:false, powerPreference:'low-power', failIfMajorPerformanceCaveat:true });
    renderer.setPixelRatio(Math.min(globalThis.devicePixelRatio || 1, 1.75));
    renderer.setSize(shape.cssWidth, shape.cssHeight, false);
    renderer.setClearColor(0x000000, 0);
    renderer.outputColorSpace = SRGBColorSpace;
    canvas.style.width = `${shape.cssWidth}px`;
    canvas.style.height = `${shape.cssHeight}px`;
    canvas.style.left = canvas.style.top = `${-shape.padding}px`;
    const uniforms = {
      uShape:{ value:shape.texture }, uTexel:{ value:new Vector2(1 / shape.width, 1 / shape.height) },
      uRange:{ value:shape.range }, uBevel:{ value:shape.bevel },
      uTime:{ value:0 }, uDock:{ value:0 }
    };
    material = new ShaderMaterial({ vertexShader, fragmentShader, uniforms, transparent:true, depthTest:false, depthWrite:false, toneMapped:false });
    geometry = new PlaneGeometry(2, 2);
    const scene = new Scene();
    const camera = new OrthographicCamera(-1, 1, 1, -1, 0, 1);
    scene.add(new Mesh(geometry, material));
    // Shader errors should restore the CSS fallback, never leave an empty logo.
    renderer.debug.onShaderError = () => { throw new Error('Glass shader compilation failed'); };
    canvas.addEventListener('webglcontextlost', contextLost);
    word.append(canvas);
    function render() {
      if (disposed) return;
      try {
        const time = now();
        uniforms.uTime.value = (time - started) / 1000;
        const progress = dockStart === null ? 0 : Math.max(0, Math.min(1, (time - dockStart) / 1350));
        uniforms.uDock.value = progress * progress * (3 - 2 * progress);
        renderer.render(scene, camera);
        word.classList.add('has-glass');
        frame = requestFrame(render);
      } catch {
        dispose();
        onError();
      }
    }
    render();
    return { dock() { dockStart = now(); }, dispose };
  } catch (error) {
    dispose();
    throw error;
  }
}
