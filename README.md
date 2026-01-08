# 🚗 Real-Time Vehicle Counter

This project implements a high-performance vehicle counting system using YOLOv8 for object detection and the SORT (Simple Online and Realtime Tracking) algorithm for consistent ID tracking. The application processes a video stream, applies a specific Region of Interest (ROI) mask, and uses a crossing-line trigger to count vehicles as they pass through designated lanes.

## 🛠️ Key Components

**YOLOv8**: Utilized for fast and accurate detection of vehicles (specifically "car," though other classes are available).

**SORT Tracker**: Implemented via sort.py to maintain persistent, unique IDs for vehicles across consecutive frames, even during brief occlusions.

**Masking (OpenCV)**: A custom mask.png is read and applied using cv2.bitwise_and() to restrict detection only to the relevant road area, improving performance and accuracy.

**Counting Logic**: Vehicles are counted using a predefined horizontal yellow line (limit). When a vehicle's bounding box center crosses this line, its unique tracker ID is recorded in a Python set to prevent double-counting.

## ✨ Performance and Accuracy

The system leverages the highly efficient YOLOv8s model for object detection. Performance benchmarks indicate a robust ability to identify and track targets:

**Detection Accuracy (mAP)**: The base YOLOv8 model achieves high performance, often resulting in >96.77% Mean Average Precision (mAP) for object detection on standard benchmarks (COCO dataset).

## ⚙️ Prerequisites & Installation

This project relies on several key computer vision libraries. Due to known binary compatibility issues in certain Python environments (especially Python 3.10), specific library versions are highly recommended for stable operation.

Recommended Environment: Python >=3.10

1. Clone the Repository

```` 
git clone [https://github.com/DivyomChaudhary/Car-Counter-CV.git](https://github.com/DivyomChaudhary/Car-Counter-CV.git)
cd Car-Counter-CV 
````


2. Install Dependencies

It is critical to install numpy and scikit-image first with the specified versions.

Force-install compatible versions for stability
pip install numpy==1.23.5 scikit-image==0.21.0


Note: Ensure you have the sort.py file (the implementation of the SORT algorithm) available in your project root directory.

## 📂 Project Structure

main.py: The core script containing the video processing loop, masking, detection, tracking, and counting logic.

sort.py: The Python file containing the Sort class implementation.

assets/: Folder containing the input video (vecteezy_traffic-BStock.mp4) and the custom ROI mask (mask.png).

YOLO-weights/: Folder where the YOLO model weights (yolov8s.pt) should be located.

## 🚀 Usage

Place your video and mask file into the assets/ directory.

Ensure your yolov8s.pt file is in the YOLO-weights/ directory (relative to main.py).

Run the main script:

````
python main.py
````


The application will display a real-time video feed with detected bounding boxes, unique tracker IDs, the counting line, and the total count displayed via cvzone.

### 🧠 Counting Logic Explained


The unique vehicle ID is added to the set_count only if its center point ````(cx, cy)```` falls within the line's Y-coordinate range ````(limit[1]-10 < cy < limit[3]+10)````. Using a Python Set ensures that even if a vehicle stays on the line across multiple frames, it is only registered once, achieving accurate **single-pass counting**.

The centroid of the bounding box is calculated using the formula:


$$cx = x_{1} + \frac{w}{2}$$

$$cy = y_{1} + \frac{h}{2}$$


where $w$ and $h$ are the width and height of the box.