APP_NAME = integrityx
GO_FILES = $(wildcard *.go)
OUTPUT_DIR = .

.PHONY: all clean

all: $(OUTPUT_DIR)/$(APP_NAME)

$(OUTPUT_DIR)/$(APP_NAME): $(GO_FILES)
	@mkdir -p $(OUTPUT_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o $(OUTPUT_DIR)/$(APP_NAME) .
	strip $(OUTPUT_DIR)/$(APP_NAME)

clean:
	rm -rf $(OUTPUT_DIR)/$(APP_NAME)

