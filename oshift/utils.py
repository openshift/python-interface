def match_params(valid_params, params, required=True):
    data = {}
    if len(valid_params) == 0:
        return data

    param_name = valid_params[0]['name']
    rp = valid_params[0]
    for rp in valid_params:
        # construct the data
        param_name = rp['name']
        if param_name == 'event':
            if isinstance(rp['valid_options'], list):
                data[param_name] = rp['valid_options'][0]
            else:
                data[param_name] = rp['valid_options']
        else:
            if required:
                data[param_name] = params[param_name]  # cart_name #params['op_type']
            elif params.get(param_name, None) is not None:
                data[param_name] = params[param_name]
            #data[param_name] = params[param_name]
    return data


def perf_test(li):
    cart_types = ['php-5.3']
    od = {
        1: {'name': 'app_create', 'params': {'app_name': 'perftest'}},
        #2: {'name': 'app_delete', 'params': {'app_name': 'perftest'}},
    }
    sod = sortedDict(od)
    #li.domain_create('blahblah')
    cart_types = ['php-5.3']  # 'php-5.3', 'ruby-1.8', 'jbossas-7']
    for cart in cart_types:
        for action in sod:
            method_call = getattr(li, action['name'])
            k, v = list(action['params'].items()[0])
            if action['name'] == 'app_create':
                method_call(v, cart)
            else:
                method_call(v)


def sortedDict(adict):
    keys = list(adict.keys())
    keys.sort()
    return map(adict.get, keys)
