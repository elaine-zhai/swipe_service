# swipe_service
## Environment setup
`git clone <this repo>` \
`cd ~/composite-service` \
`python3 -m venv venv` \
`source venv/bin/activate` \
`pip install -r requirements.txt`

## To run
`uvicorn swipe_service:app --reload --host 0.0.0.0 --port 8002`
