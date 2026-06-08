import os
import time
import threading

# Low-latency RTSP options for OpenCV/FFmpeg
os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = (
    "rtsp_transport;tcp|"
    "fflags;nobuffer|"
    "flags;low_delay|"
    "max_delay;500000|"
    "stimeout;3000000"
)

import cv2
from flask import Flask, Response, jsonify

app = Flask(__name__)

RTSP_URL = os.getenv("RTSP_URL", "rtsp://192.168.100.86/live/profile.0")

OUTPUT_WIDTH = int(os.getenv("OUTPUT_WIDTH", "640"))
OUTPUT_HEIGHT = int(os.getenv("OUTPUT_HEIGHT", "360"))
OUTPUT_FPS = float(os.getenv("OUTPUT_FPS", "12"))
JPEG_QUALITY = int(os.getenv("JPEG_QUALITY", "50"))
STALE_AFTER_SECONDS = float(os.getenv("STALE_AFTER_SECONDS", "3"))

latest_frame = None
latest_frame_time = 0.0
latest_jpeg = None
latest_jpeg_time = 0.0
camera_online = False

frame_lock = threading.Lock()
jpeg_lock = threading.Lock()
state_lock = threading.Lock()


def now_monotonic():
    return time.monotonic()


def is_fresh(timestamp):
    return timestamp > 0 and (now_monotonic() - timestamp) <= STALE_AFTER_SECONDS


def set_camera_online(is_online):
    global camera_online
    with state_lock:
        camera_online = is_online


def get_camera_online():
    with state_lock:
        return camera_online


def clear_cached_frames():
    global latest_frame, latest_frame_time, latest_jpeg, latest_jpeg_time

    with frame_lock:
        latest_frame = None
        latest_frame_time = 0.0

    with jpeg_lock:
        latest_jpeg = None
        latest_jpeg_time = 0.0


def mark_camera_offline(clear_cache=True):
    set_camera_online(False)

    if clear_cache:
        clear_cached_frames()


def has_fresh_jpeg():
    with jpeg_lock:
        return latest_jpeg is not None and is_fresh(latest_jpeg_time)


def camera_reader():
    global latest_frame, latest_frame_time

    while True:
        cap = None

        try:
            cap = cv2.VideoCapture(RTSP_URL, cv2.CAP_FFMPEG)
            cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

            if not cap.isOpened():
                mark_camera_offline(clear_cache=True)
                time.sleep(1)
                continue

            while True:
                success, frame = cap.read()

                if not success or frame is None:
                    mark_camera_offline(clear_cache=True)
                    break

                with frame_lock:
                    latest_frame = frame
                    latest_frame_time = now_monotonic()

                set_camera_online(True)

        except Exception as error:
            print("Camera reader error:", error)
            mark_camera_offline(clear_cache=True)
            time.sleep(1)

        finally:
            if cap is not None:
                cap.release()

        time.sleep(1)


def frame_encoder():
    global latest_jpeg, latest_jpeg_time

    delay = 1.0 / OUTPUT_FPS

    while True:
        start_time = time.time()

        with frame_lock:
            frame = None if latest_frame is None else latest_frame.copy()
            frame_time = latest_frame_time

        if frame is not None and is_fresh(frame_time):
            frame = cv2.resize(frame, (OUTPUT_WIDTH, OUTPUT_HEIGHT))

            success, buffer = cv2.imencode(
                ".jpg",
                frame,
                [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY]
            )

            if success:
                with jpeg_lock:
                    latest_jpeg = buffer.tobytes()
                    latest_jpeg_time = now_monotonic()

                set_camera_online(True)
        else:
            with jpeg_lock:
                latest_jpeg = None
                latest_jpeg_time = 0.0

            set_camera_online(False)

        elapsed = time.time() - start_time
        time.sleep(max(0, delay - elapsed))


def generate_mjpeg():
    delay = 1.0 / OUTPUT_FPS

    while True:
        with jpeg_lock:
            frame_bytes = latest_jpeg
            frame_time = latest_jpeg_time

        if frame_bytes is None or not is_fresh(frame_time):
            break

        yield (
            b"--frame\r\n"
            b"Content-Type: image/jpeg\r\n"
            b"Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n"
            b"Pragma: no-cache\r\n\r\n" +
            frame_bytes +
            b"\r\n"
        )

        time.sleep(delay)


@app.route("/")
def home():
    online = get_camera_online() and has_fresh_jpeg()

    return jsonify({
        "status": "RTSP bridge running",
        "video": "/video",
        "snapshot": "/shot.jpg",
        "camera_online": online,
        "output_resolution": f"{OUTPUT_WIDTH}x{OUTPUT_HEIGHT}",
        "output_fps": OUTPUT_FPS,
        "jpeg_quality": JPEG_QUALITY,
        "stale_after_seconds": STALE_AFTER_SECONDS
    })


@app.route("/video")
def video():
    if not has_fresh_jpeg():
        return "Camera offline", 503

    return Response(
        generate_mjpeg(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


@app.route("/shot.jpg")
def snapshot():
    with jpeg_lock:
        frame_bytes = latest_jpeg
        frame_time = latest_jpeg_time

    if frame_bytes is None or not is_fresh(frame_time):
        return "Camera offline", 503

    return Response(
        frame_bytes,
        mimetype="image/jpeg",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


@app.route("/status")
def status():
    fresh_jpeg = has_fresh_jpeg()
    online = get_camera_online() and fresh_jpeg

    if not online:
        set_camera_online(False)

    return jsonify({
        "camera_online": online,
        "has_frame": fresh_jpeg
    })


if __name__ == "__main__":
    reader_thread = threading.Thread(target=camera_reader, daemon=True)
    encoder_thread = threading.Thread(target=frame_encoder, daemon=True)

    reader_thread.start()
    encoder_thread.start()

    app.run(host="0.0.0.0", port=8090, threaded=True)
