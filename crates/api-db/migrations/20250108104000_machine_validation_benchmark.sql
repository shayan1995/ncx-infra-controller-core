UPDATE
    machine_validation_tests
SET
    pre_condition = '/opt/nico/benchpress-cuda-pre-setup.sh',
    img_name = '',
    container_arg = ''
where
    test_id = 'nico_CudaSample';