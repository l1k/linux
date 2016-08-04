obj-${CONFIG_THUNDERBOLT} := thunderbolt.o
thunderbolt-objs := nhi.o ctl.o tb.o switch.o cap.o path.o tunnel_pci.o eeprom.o
thunderbolt-objs += adapter_pci.o domain.o dma_port.o icm.o property.o xdomain.o
ifdef CONFIG_ACPI
ifdef CONFIG_PM
thunderbolt-objs += pm_apple.o
endif
endif
