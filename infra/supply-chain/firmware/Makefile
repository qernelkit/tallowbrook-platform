# Depot gateway firmware: build with west, then sign the image for MCUboot.
# The signing key lives only on the offline signing host.

IMGTOOL      ?= imgtool
WEST         ?= west
BOARD        ?= depot_gateway_rev3
SIGNING_KEY  ?= keys/gateway-image-signing.pem
VERSION      ?= 0.0.0
BUILD_DIR    ?= build
IMAGE        := $(BUILD_DIR)/zephyr/zephyr.bin
SIGNED_IMAGE := $(BUILD_DIR)/gateway-$(VERSION).signed.bin

.PHONY: all build signed-image signing-key clean

all: signed-image

build:
	$(WEST) build -b $(BOARD) -d $(BUILD_DIR) app -- -DCONFIG_GATEWAY_VERSION=\"$(VERSION)\"

# Run once on the offline signing host, then copy the public half into the
# bootloader configuration.
signing-key:
	$(IMGTOOL) keygen -k $(SIGNING_KEY) -t ecdsa-p256

signed-image: build
	$(IMGTOOL) sign --key $(SIGNING_KEY) --header-size 0x200 --slot-size 0x60000 \
		--version $(VERSION) --align 8 --pad-header \
		--sha 256 \
		$(IMAGE) $(SIGNED_IMAGE)
	@echo "signed image: $(SIGNED_IMAGE)"

clean:
	rm -rf $(BUILD_DIR)
