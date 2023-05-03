
# Pythia-Alpha - OG Code
<p>Machine Learning Algo for Detecting Bad Network Traffic</p>

## Internal Usage
* `sudo python3 cap.py` - Capture UDP and TCP Traffic to json file for Training, Make sure to change the Label accordingly.
* `python3 model.py` - Train the TCP and UDP Models based on Labeled data collected.
* `sudo python3 prod.py` - Dry run the Algo on live network traffic of device with scores and external packet dropping.

## File Map
* `data_tcp.json` - Labeled Training TCP Traffic Data
* `data_udp.json` - Labeled Training UDP Traffic Data
* `model_tcp.pkl` - TCP Trained Model
* `model_udp.pkl` - UDP Trained Model