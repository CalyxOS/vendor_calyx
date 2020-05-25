package android
type Product_variables struct {
	Additional_gralloc_10_usage_bits struct {
		Cppflags []string
	}
	Qcom_um_soong_namespace struct {
		Cflags []string
		Header_libs []string
	}
	Should_wait_for_qsee struct {
		Cflags []string
	}
	Supports_extended_compress_format struct {
		Cflags []string
	}
	Supports_hw_fde struct {
		Cflags []string
		Header_libs []string
		Shared_libs []string
	}
	Supports_hw_fde_perf struct {
		Cflags []string
	}
	Uses_qti_camera_device struct {
		Cppflags []string
		Shared_libs []string
	}
}

type ProductVariables struct {
	Additional_gralloc_10_usage_bits  *string `json:",omitempty"`
	Qcom_um_soong_namespace  *string `json:",omitempty"`
	Should_wait_for_qsee  *bool `json:",omitempty"`
	Supports_extended_compress_format  *bool `json:",omitempty"`
	Supports_hw_fde  *bool `json:",omitempty"`
	Supports_hw_fde_perf  *bool `json:",omitempty"`
	Uses_qti_camera_device  *bool `json:",omitempty"`
}
