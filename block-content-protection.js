// --- Settings Initialization ---
let bcp_settings = {};
const settingsElement = document.getElementById('bcp-settings-data');
if (settingsElement) {
    try {
        bcp_settings = JSON.parse(settingsElement.textContent);
    } catch (e) {
        console.error("BCP Error: Could not parse settings data.", e);
    }
}

// Use a WeakSet to keep track of videos that have already been processed
const processedVideos = new WeakSet();

// --- Core Video Protection Logic ---
const protectVideo = (video) => {
    // Exit if the video has already been processed or is marked as protected
    if (processedVideos.has(video) || video.dataset.bcpProtected === 'true') return;
    processedVideos.add(video);
    video.dataset.bcpProtected = 'true';

    // Disable native controls that are not needed
    video.setAttribute('controlsList', 'nodownload');
    video.setAttribute('disablePictureInPicture', 'true');

    // Create a wrapper for the video and its watermark
    let wrapper = document.createElement('div');
    wrapper.classList.add('bcp-watermark-wrapper');
    // Insert the wrapper before the video and then move the video inside it
    video.parentNode.insertBefore(wrapper, video);
    wrapper.appendChild(video);

    // Apply watermark if enabled in settings
    if (bcp_settings.enable_video_watermark && bcp_settings.watermark_text) {
        applyWatermark(wrapper);
    }

    // Add the custom fullscreen button
    addCustomFullscreenButton(wrapper);

    // Secure the video source if download protection is enabled
    if (bcp_settings.disable_video_download) {
        protectVideoSource(video);
    }
};

const protectVideoSource = (video) => {
    const originalSrc = video.getAttribute('src') || video.querySelector('source')?.getAttribute('src');
    // Only process if there's a source and it's not already a blob URL
    if (originalSrc && !originalSrc.startsWith('blob:')) {
        // Fetch the video as a blob to obscure the direct URL
        fetch(originalSrc, { credentials: 'omit' })
            .then(response => {
                if (!response.ok) throw new Error(`BCP: Network error fetching video: ${response.statusText}`);
                return response.blob();
            })
            .then(blob => {
                video.src = URL.createObjectURL(blob);
            })
            .catch(err => {
                console.error('BCP Error:', err);
                video.setAttribute('src', originalSrc); // Restore original source on failure
            });
    }
}

// --- Watermark & Fullscreen UI ---
const applyWatermark = (wrapper) => {
    // Remove any existing watermark to prevent duplicates
    wrapper.querySelector('.bcp-watermark, .bcp-wm-style-pattern')?.remove();
    const { watermark_opacity = 0.5, watermark_animated = true, watermark_position = 'top_left', watermark_style = 'text', watermark_text, watermark_count = 30 } = bcp_settings;

    const element = document.createElement('div');
    if (watermark_style === 'pattern') {
        element.className = 'bcp-wm-style-pattern';
        element.style.opacity = watermark_opacity;
        // Create multiple spans for the pattern effect
        for (let i = 0; i < watermark_count; i++) {
            const span = document.createElement('span');
            span.className = 'bcp-watermark-pattern-span';
            span.textContent = watermark_text;
            element.appendChild(span);
        }
    } else {
        // Determine the correct class based on whether animation is enabled
        const positionClass = watermark_animated ? 'bcp-wm-position-animated' : `bcp-wm-position-${watermark_position}`;
        element.className = `bcp-watermark bcp-wm-style-text ${positionClass}`;
        element.textContent = watermark_text;
        element.style.opacity = watermark_opacity;
    }
    wrapper.appendChild(element);
};

const addCustomFullscreenButton = (wrapper) => {
    const button = document.createElement('button');
    button.className = 'bcp-custom-fullscreen-btn';
    button.setAttribute('aria-label', 'Enter Fullscreen');
    button.innerHTML = '<svg viewbox="0 0 18 18"><path d="M4.5 11H3v4h4v-1.5H4.5V11zM3 7h1.5V4.5H7V3H3v4zm10.5 6.5H11V15h4v-4h-1.5v2.5zM11 3v1.5h2.5V7H15V3h-4z"></path></svg>';
    wrapper.appendChild(button);

    // Handle cross-browser fullscreen requests
    button.addEventListener('click', () => {
        if (!document.fullscreenElement && !document.webkitFullscreenElement) {
            if (wrapper.requestFullscreen) wrapper.requestFullscreen();
            else if (wrapper.webkitRequestFullscreen) wrapper.webkitRequestFullscreen();
        } else {
            if (document.exitFullscreen) document.exitFullscreen();
            else if (document.webkitExitFullscreen) document.webkitExitFullscreen();
        }
    });
};

// --- General Protection Event Handlers ---
const preventDefault = e => e.preventDefault();

const handleKeydown = (e) => {
    const key = e.key.toUpperCase();
    const ctrl = e.ctrlKey || e.metaKey;

    // Block developer tools shortcuts
    if (bcp_settings.disable_devtools && (e.key === 'F12' || (ctrl && e.shiftKey && ['I', 'J', 'C'].includes(key)) || (ctrl && key === 'U'))) {
        e.preventDefault();
    }
    // Block screenshot shortcuts
    if (bcp_settings.disable_screenshot && (e.key === 'PrintScreen' || (ctrl && e.shiftKey && ['3', '4', 'S'].includes(key)))) {
        e.preventDefault();
        document.body.classList.add('bcp-screenshot-detected');
        if (bcp_settings.enable_custom_messages && bcp_settings.screenshot_alert_message) {
            alert(bcp_settings.screenshot_alert_message);
        }
        setTimeout(() => document.body.classList.remove('bcp-screenshot-detected'), 1000);
    }
};

// Intercept screen recording attempts
const handleScreenRecording = () => {
    if (!bcp_settings.video_screen_record_block) return;

    // Black out video when tab loses focus
    document.addEventListener('visibilitychange', () => {
        const isPageHidden = document.hidden;
        document.querySelectorAll('video').forEach(v => {
            const wrapper = v.closest('.bcp-watermark-wrapper');
            if (wrapper) {
                if (isPageHidden) {
                    wrapper.classList.add('bcp-recording-detected');
                } else {
                    wrapper.classList.remove('bcp-recording-detected');
                }
            }
        });
    });

    if (!navigator.mediaDevices?.getDisplayMedia) return;

    const originalGetDisplayMedia = navigator.mediaDevices.getDisplayMedia;
    navigator.mediaDevices.getDisplayMedia = async function(...args) {
        // When a recording attempt is detected, apply a class to blur the video
        document.querySelectorAll('video').forEach(v => v.closest('.bcp-watermark-wrapper')?.classList.add('bcp-recording-detected'));
        try {
            const stream = await originalGetDisplayMedia.apply(this, args);
            // When the stream ends (user stops recording), remove the class
            stream.getTracks().forEach(track => {
                track.onended = () => document.querySelectorAll('.bcp-recording-detected').forEach(el => el.classList.remove('bcp-recording-detected'));
            });
            return stream;
        } catch (err) {
            // If the user cancels the recording, remove the class
            document.querySelectorAll('.bcp-recording-detected').forEach(el => el.classList.remove('bcp-recording-detected'));
            throw err;
        }
    };
};

// --- Initialization ---
const initProtection = () => {
    // Apply protection to all existing video elements on the page
    document.querySelectorAll('video').forEach(protectVideo);
    // Disable text selection if enabled
    if (bcp_settings.disable_text_selection) {
        document.body.style.cssText += 'user-select:none;-webkit-user-select:none;';
    }
    // Apply enhanced CSS protection if enabled
    if (bcp_settings.enhanced_protection) {
        document.body.classList.add('bcp-enhanced-protection');
    }
};

// Use a MutationObserver to detect and protect videos added to the DOM dynamically
const observer = new MutationObserver(mutations => {
    mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
            if (node.nodeType === 1) { // Element node
                if (node.tagName === 'VIDEO') {
                    protectVideo(node);
                } else {
                    // Also check for videos within newly added complex elements
                    node.querySelectorAll?.('video').forEach(protectVideo);
                }
            }
        });
    });
});

// Main execution block
const BCP_Init = () => {
    // Run protection when the DOM is ready
    // if (document.readyState === 'loading') {
    //     document.addEventListener('DOMContentLoaded', initProtection);
    // } else {
    //     initProtection();
    // }

    // Start observing for future DOM changes
    // observer.observe(document.body, { childList: true, subtree: true });

    // Add global event listeners based on settings
    if (bcp_settings.disable_right_click) document.addEventListener('contextmenu', preventDefault, false);
    if (bcp_settings.disable_copy) document.addEventListener('copy', preventDefault, false);
    if (bcp_settings.disable_image_drag) document.addEventListener('dragstart', e => { if (e.target.tagName === 'IMG') e.preventDefault(); }, false);
    if (bcp_settings.disable_devtools || bcp_settings.disable_screenshot) {
        document.addEventListener('keydown', handleKeydown);
    }

    handleScreenRecording();
};

BCP_Init();
