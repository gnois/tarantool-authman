local activation_token = {}

local digest = require('digest')
local validator = require('authman.validator')


-----
-- token (user_id, code)
-----
function activation_token.model(config)
    local model = {}

    model.SPACE_NAME = config.spaces.activation_token.name

    model.PRIMARY_INDEX = 'primary'

    model.USER_ID = 1
    model.CODE = 2

    function model.get_space()
        return box.space[model.SPACE_NAME]
    end

    function model.get_by_user_id(user_id)
        return model.get_space():get(user_id)
    end

    function model.delete(user_id)
        if validator.not_empty_string(user_id) then
            return model.get_space():delete({user_id})
        end
    end

    local function get_expiration_time()
        return os.time() + config.change_lifetime
    end

    function model.generate(user_id)
        local token = digest.md5_hex(user_id .. os.time() .. config.activation_secret)
        model.get_space():upsert({user_id, token}, {{'=', 2, token}})
        return token
    end

    function model.is_valid(user_token, user_id)
        local token_tuple = model.get_by_user_id(user_id)
        if token_tuple and token_tuple[2] == user_token then
            return true
        end
        return false
    end

    function model.delete(user_id)
        return model.get_space():delete(user_id)
    end

    return model
end

return activation_token
