import os
import time
import threading

import cv2
from flask import Flask, Response, jsonify

app = Flask(__name__)

RTSP_URL = os.getenv("RTSP_URL", "rtsp://192.168.100.86/live/profile.0")

latest_frame = None
camera_online = False
frame_lock = threading.Lock()


def camera_reader():
    global latest_frame, camera_online

    while True:
        cap = None

        try:
            cap = cv2.VideoCapture(RTSP_URL, cv2.CAP_FFMPEG)

            if not cap.isOpened():
                camera_online = False
                time.sleep(3)
                continue

            camera_online = True

            while True:
                success, frame = cap.read()

                if not success or frame is None:
                    camera_online = False
                    break

                with frame_lock:
                    latest_frame = frame.copy()

                time.sleep(0.03)

        except Exception as error:
            print("Camera reader error:", error)
            camera_online = False
            time.sleep(3)

        finally:
            if cap is not None:
                cap.release()

        time.sleep(2)


def generate_mjpeg():
    global latest_frame

    while True:
        with frame_lock:
            frame = None if latest_frame is None else latest_frame.copy()

        if frame is None:
            time.sleep(0.2)
            continue

        success, buffer = cv2.imencode(".jpg", frame)

        if not success:
            continue

        frame_bytes = buffer.tobytes()

        yield (
            b"--frame\r\n"
            b"Content-Type: image/jpeg\r\n\r\n" + frame_bytes + b"\r\n"
        )


@app.route("/")
def home():
    return jsonify({
        "status": "RTSP bridge running",
        "video": "/video",
        "snapshot": "/shot.jpg",
        "camera_online": camera_online
    })


@app.route("/video")
def video():
    return Response(
        generate_mjpeg(),
        mimetype="multipart/x-mixed-replace; boundary=frame"
    )


@app.route("/shot.jpg")
def snapshot():
    with frame_lock:
        frame = None if latest_frame is None else latest_frame.copy()

    if frame is None:
        return "Camera offline", 503

    success, buffer = cv2.imencode(".jpg", frame)

    if not success:
        return "Snapshot failed", 500

    return Response(buffer.tobytes(), mimetype="image/jpeg")


@app.route("/status")
def status():
    return jsonify({
        "camera_online": camera_online,
        "has_frame": latest_frame is not None
    })


if __name__ == "__main__":
    reader_thread = threading.Thread(target=camera_reader, daemon=True)
    reader_thread.start()

    app.run(host="0.0.0.0", port=8090, threaded=True)