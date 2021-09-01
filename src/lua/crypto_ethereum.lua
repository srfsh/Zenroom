--[[
--This file is part of zenroom
--
--Copyright (C) 2021 Dyne.org foundation
--designed, written and maintained by Alberto Lerda and Denis Roio
--
--This program is free software: you can redistribute it and/or modify
--it under the terms of the GNU Affero General Public License v3.0
--
--This program is distributed in the hope that it will be useful,
--but WITHOUT ANY WARRANTY; without even the implied warranty of
--MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--GNU Affero General Public License for more details.
--
--Along with this program you should have received a copy of the
--GNU Affero General Public License v3.0
--If not, see http://www.gnu.org/licenses/agpl.txt
--
--Last modified by Denis Roio
--on Wednesday, 1st September 2021
--]]

-- crypto API:
-- pk, sk = keygen_eth()

-- signed_tx = sign_eth_tx(sk, tx)
-- rawtx = encode_eth_rlp(signed_tx)

-- signed_tx = decode_eth_rlp(rawtx)
-- assert( verify(eth_tx(pk, signed_tx)))

local function encodeRLP(data)
    local header
    local res
    local byt

    if type(data) == 'table' then
        -- empty octet
        res = O.new()
        for _, v in pairs(data) do
            res = res .. encodeRLP(v)
        end
        if #res < 56 then
            res = INT.new(192+#res):octet() .. res
        else
            -- Length of the result to be saved before the bytes themselves
            byt = INT.new(#res):octet()
            header = INT.new(247+#byt):octet() .. byt

        end
    elseif iszen(type(data)) then
        -- Octet aka byte array
        res = data:octet()

        -- Empty octet?
        -- index single bytes of an octet
        byt = INT.new(0)
        if #res > 0 then
            byt = INT.new( res:chop(1) )
        end

        if #res ~= 1 or byt >= INT.new(128) then
            if #res < 56 then
                header = INT.new(128+#res):octet()
            else
                -- Length of the result to be saved before the bytes themselves
                byt = INT.new(#res):octet()
                header = INT.new(183+#byt):octet() .. byt
            end
        end

    else
        error("Invalid data type for ETH RLP encoder: "..type(data))
    end
    if header then
        res = header .. res
    end
    return res
end

-- i is the position from which we start to parse
-- return a table with
-- * res which is the content read
-- * idx which is the position of the next byte to read
local function decodeRLPgeneric(rlp, i)
    local byt, bytInt, res, idx
    if type(rlp) == 'table' then error("crypto ethereum error decoding RLP: is a table", 3) end
    if type(rlp) ~= 'zenroom.octet' then error("crypto ethereum error decoding RLP wrong type: "..type(rlp), 3) end
    byt = rlp:sub(i, i)
    idx=i+1
    bytInt = tonumber(byt:hex(), 16)

    if bytInt < 128 then
        res = byt
    elseif bytInt <= 183 then
        idx = i+bytInt-128+1
        if bytInt == 128 then
            res = O.new()
        else
            res = rlp:sub(i+1, idx-1)
        end

    elseif bytInt < 192 then
        local sizeEnd = bytInt-183;
        local size = tonumber(rlp:sub(i+1, i+sizeEnd):hex(), 16)
        idx = i+sizeEnd+size+1
        res = rlp:sub(i+sizeEnd+1, idx-1)
    else -- it is a tuple
        local j
        if bytInt <= 247 then
            idx = i+bytInt-192+1 -- total number of bytes
        else -- decode big endian encoding
            local sizeEnd
            sizeEnd = bytInt-247;
            local size = tonumber(rlp:sub(i+1, i+sizeEnd):hex(), 16)
            idx = i+sizeEnd+size+1
            i=i+sizeEnd
        end
        i=i+1 -- initial position
        j=1 -- index inside res
        res = {}
        -- decode the tuple in a table
        while i < idx do
            local readNext
            readNext = decodeRLPgeneric(rlp, i)
            res[j] = readNext.res
            j = j+1
            i = readNext.idx
        end
    end
    return {
        res=res,
        idx=idx
    }
end

function encode_eth_rlp(tx)
    if luatype(tx) ~= 'table' then error("encode_eth_rlp: argument is not a table", 2) end
    return encodeRLP({tx.nonce, tx.gasPrice, tx.gasLimit, tx.to,
                        tx.value, tx.data, tx.v, tx.r, tx.s})
end

function decode_eth_rlp(rlp)
    if luatype(rlp) == 'table' then error("decode_eth_rlp: argument is a table", 2) end
    local t = decodeRLPgeneric(rlp, 1).res
    return {
        nonce=t[1],
        gasPrice=INT.new(t[2]),
        gasLimit=INT.new(t[3]),
        to=t[4],
        value=t[5],
        data=t[6],
        v=INT.new(t[7]),
        r=t[8],
        s=t[9]
    }
end

-- from milagro's ROM, halved (works only with SECP256K1 curve)
-- const BIG_256_28 CURVE_Order_SECP256K1=
-- {0x364141,0xD25E8CD,0x8A03BBF,0xDCE6AF4,0xFFEBAAE,0xFFFFFFF,0xFFFFFFF,0xFFFFFFF,0xFFFFFFF,0xF};
local half_secp256k1_order = 
    INT.new(O.from_hex('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0'))

local function signEcdsaEth(sk, data)
    local sig
    repeat
        sig = ECDH.sign_hashed(sk, data, #data)
    until(INT.new(sig.s) < half_secp256k1_order);

    return sig
end

-- modify the input transaction
function sign_eth_tx(sk, tx)
    local H, txHash, sig, pk, x, y, two, res
    if luatype(tx) ~= 'table' then error("sign_eth_tx error: 2nd argument is not a table", 2) end
    if tx.r and #tx.r ~= 0 then
        error("sign_eth_tx error: transaction is already signed", 2) end
    if tx.s and #tx.s ~= 0 then
        error("sign_eth_tx error: transaction is already signed", 2) end

    H = HASH.new('keccak256')
    txHash = H:process(encode_eth_rlp(tx))

    sig = signEcdsaEth(sk, txHash);

    pk = ECDH.pubgen(sk)
    x, y = ECDH.pubxy(pk);

    two = INT.new(2);
    res = tx
    res.v = two * INT.new(tx.v) + INT.new(35) + INT.new(y) % two
    res.r = sig.r
    res.s = sig.s

    return res

end

-- encodedTx = encodeSignedTransaction(from, tx)

-- print(encodedTx:hex())
-- decodedTx = decodeTransaction(encodedTx)

-- fields = {"nonce", "gasPrice", "gasLimit", "to",
-- "value", "data"}
-- for _, v in pairs(fields) do
--     assert(tx[v] == decodedTx[v])
-- end

-- Verify the signature of a decoded tx
-- Simple replay attack protection: implements EIP-155
-- https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
function verify_eth_tx(pk, txSigned)
    local fields, H, txHash, tx
    if luatype(txSigned) ~= 'table' then error("verify_eth_tx error: 2nd argument is not a table", 2) end
    if txSigned.r and #txSigned.r == 0 then
        error("sign_eth_tx error: transaction is already signed", 2) end
    if txSigned.s and #txSigned.s == 0 then
        error("sign_eth_tx error: transaction is already signed", 2) end

    fields = {"nonce", "gasPrice", "gasLimit", "to", "value", "data"}

    -- construct the transaction which was signed
    tx = {}
    for _, v in pairs(fields) do
        tx[v] = txSigned[v]
    end
    tx["v"] = (txSigned["v"]-INT.new(35)) / INT.new(2)
    tx["r"] = O.new()
    tx["s"] = O.new()


    H = HASH.new('keccak256')
    txHash = H:process(encode_eth_rlp(tx))

    sig = {
        r=txSigned["r"],
        s=txSigned["s"]
    }

    return ECDH.verify_hashed(pk, txHash, sig, #txHash)
end