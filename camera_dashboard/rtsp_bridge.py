import os
import time
import threading

# Low-latency RTSP options for OpenCV/FFmpeg
os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = (
    "rtsp_transport;tcp|"
    "fflags;nobuffer|"
    "flags;low_delay|"
    "max_delay;500000"
)

import cv2
from flask import Flask, Response, jsonify

app = Flask(__name__)

RTSP_URL = os.getenv("RTSP_URL", "rtsp://192.168.100.86/live/profile.0")

OUTPUT_WIDTH = int(os.getenv("OUTPUT_WIDTH", "640"))
OUTPUT_HEIGHT = int(os.getenv("OUTPUT_HEIGHT", "360"))
OUTPUT_FPS = float(os.getenv("OUTPUT_FPS", "12"))
JPEG_QUALITY = int(os.getenv("JPEG_QUALITY", "50"))

latest_frame = None
latest_jpeg = None
camera_online = False

frame_lock = threading.Lock()
jpeg_lock = threading.Lock()


def camera_reader():
    global latest_frame, camera_online

    while True:
        cap = None

        try:
            cap = cv2.VideoCapture(RTSP_URL, cv2.CAP_FFMPEG)
            cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

            if not cap.isOpened():
                camera_online = False
                time.sleep(1)
                continue

            camera_online = True

            while True:
                success, frame = cap.read()

                if not success or frame is None:
                    camera_online = False
                    break

                # Always keep only the newest frame
                with frame_lock:
                    latest_frame = frame

        except Exception as error:
            print("Camera reader error:", error)
            camera_online = False
            time.sleep(1)

        finally:
            if cap is not None:
                cap.release()

        time.sleep(1)


def frame_encoder():
    global latest_jpeg, camera_online

    delay = 1.0 / OUTPUT_FPS

    while True:
        start_time = time.time()

        with frame_lock:
            frame = None if latest_frame is None else latest_frame.copy()

        if frame is not None:
            frame = cv2.resize(frame, (OUTPUT_WIDTH, OUTPUT_HEIGHT))

            success, buffer = cv2.imencode(
                ".jpg",
                frame,
                [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY]
            )

            if success:
                with jpeg_lock:
                    latest_jpeg = buffer.tobytes()
                camera_online = True

        elapsed = time.time() - start_time
        time.sleep(max(0, delay - elapsed))


def generate_mjpeg():
    delay = 1.0 / OUTPUT_FPS

    while True:
        with jpeg_lock:
            frame_bytes = latest_jpeg

        if frame_bytes is not None:
            yield (
                b"--frame\r\n"
                b"Content-Type: image/jpeg\r\n"
                b"Cache-Control: no-cache\r\n\r\n" +
                frame_bytes +
                b"\r\n"
            )

        time.sleep(delay)


@app.route("/")
def home():
    return jsonify({
        "status": "RTSP bridge running",
        "video": "/video",
        "snapshot": "/shot.jpg",
        "camera_online": camera_online,
        "output_resolution": f"{OUTPUT_WIDTH}x{OUTPUT_HEIGHT}",
        "output_fps": OUTPUT_FPS,
        "jpeg_quality": JPEG_QUALITY
    })


@app.route("/video")
def video():
    return Response(
        generate_mjpeg(),
        mimetype="multipart/x-mixed-replace; boundary=frame"
    )


@app.route("/shot.jpg")
def snapshot():
    with jpeg_lock:
        frame_bytes = latest_jpeg

    if frame_bytes is None:
        return "Camera offline", 503

    return Response(frame_bytes, mimetype="image/jpeg")


@app.route("/status")
def status():
    return jsonify({
        "camera_online": camera_online,
        "has_frame": latest_jpeg is not None
    })


if __name__ == "__main__":
    reader_thread = threading.Thread(target=camera_reader, daemon=True)
    encoder_thread = threading.Thread(target=frame_encoder, daemon=True)

    reader_thread.start()
    encoder_thread.start()

    app.run(host="0.0.0.0", port=8090, threaded=True)