-- This file is part of Zenroom (https://zenroom.dyne.org)
--
-- Copyright (C) 2020-2021 Dyne.org foundation
-- designed and written by Denis Roio
-- with help by Alberto Ibrisevich and Andrea D'Intino
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as
-- published by the Free Software Foundation, either version 3 of the
-- License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
-- Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public
-- License along with this program.  If not, see
-- <https://www.gnu.org/licenses/>.

ABC = require_once('crypto_credential')

require_once('zencode_credential')

G2 = ECP2.generator()

local function import_reflow_seal_fingerprints_f(o)
    if not o then
        return {}
    end
    local rawarr = deepmap(CONF.input.encoding.fun, o)
    local arr = {}
    for _, v in ipairs(rawarr) do
        table.insert(arr, ECP.new(v))
    end
    return arr
end

local function import_reflow_seal_f(obj)
   local f
   if obj.fingerprints then
	  f = import_reflow_seal_fingerprints_f(obj.fingerprints)
   else f = nil end
   return {
	  identity = ZEN.get(obj, 'identity', ECP.new),
	  SM = ZEN.get(obj, 'SM', ECP.new),
	  verifier = ZEN.get(obj, 'verifier', ECP2.new),
	  fingerprints = f
   }
end

ZEN.add_schema(
    {
        reflow_public_key = function(obj)
		   return ZEN.get(obj, '.', ECP2.new)
        end,

        reflow_seal = import_reflow_seal_f,

        reflow_signature = function(obj)
            return {
                identity = ZEN.get(obj, 'identity', ECP.new),
                signature = ZEN.get(obj, 'signature', ECP.new),
                proof = import_credential_proof_f(obj.proof),
                zeta = ZEN.get(obj, 'zeta', ECP.new)
            }
        end,
		reflow_identity = function(obj)
		   return ZEN.get(obj, '.', ECP.new)
		end,
		material_passport = function(obj)
		   return {
			  seal = import_reflow_seal_f(obj.seal),
			  proof = import_credential_proof_f(obj.proof),
			  zeta = ZEN.get(obj, 'zeta', ECP.new)
		   }
		end
    }
)

local function _makeuid(src)
   local uid
   if luatype(src) == 'table' then
	  uid = ECP.hashtopoint(ZEN.serialize(src))
   else
	  uid = ECP.hashtopoint(src)
   end
   return(uid)
end

When(
    'create the reflow key',
    function()
        -- keygen: δ = r.O ; γ = δ.G2
        initkeys 'reflow'
        ACK.keys.reflow = INT.random() -- BLS secret signing key
    end
)

When(
    'create the reflow public key',
    function()
        empty 'reflow public key'
        havekey 'reflow'
        ACK.reflow_public_key = G2 * ACK.keys.reflow
    end
)

When(
    "aggregate the reflow public key from array ''",
    function(arr)
        empty 'reflow public key'
        local s = have(arr)
        for _, v in pairs(s) do
            if not ACK.reflow_public_key then
                ACK.reflow_public_key = v
            else
                ACK.reflow_public_key = ACK.reflow_public_key + v
            end
        end
    end
)

When(
    "create the reflow identity of ''",
    function(doc)
        empty 'reflow identity'
        local src = have(doc)
		ACK.reflow_identity = _makeuid(have(doc))
    end
)

local function _create_reflow_seal_f(uid)
    empty 'reflow seal'
    have(uid)
    have 'reflow public key'
    local UID = ACK[uid]
    ZEN.assert(type(UID) == 'zenroom.ecp',
                            "Invalid reflow identity: "
                            ..uid.." ("..type(UID)..")")
    local r = INT.random()
    ACK.reflow_seal = {
        identity = UID,
        SM = UID * r,
        verifier = ACK.reflow_public_key + G2 * r
    }
end

When(
    "create the reflow seal with identity ''",
    _create_reflow_seal_f)
When("create the reflow seal",
    function() _create_reflow_seal_f('reflow identity') end)

When(
    'create the reflow signature',
    function()
        empty 'reflow signature'
        have 'reflow seal'
        have 'issuer public key'
		havekey 'reflow'
		havekey 'credential'
		-- aggregate all credentials
        local pubcred = false
        for _, v in pairs(ACK.issuer_public_key) do
            if not pubcred then
                pubcred = v
            else
                pubcred = {
                    pubcred.alpha + v.alpha,
                    pubcred.beta + v.beta
                }
            end
        end
        local p, z =
            ABC.prove_cred_uid(
            pubcred,
            ACK.credentials,
            ACK.keys.credential,
            ACK.reflow_seal.identity
        )
        ACK.reflow_signature = {
            identity = ACK.reflow_seal.identity,
            signature = ACK.reflow_seal.identity * ACK.keys.reflow,
            proof = p,
            zeta = z
        }
    end
)

When(
    'prepare credentials for verification',
    function()
        have 'credential'
        local res = false
        for _, v in pairs(ACK.issuer_public_key) do
            if not res then
                res = {alpha = v.alpha, beta = v.beta}
            else
                res.alpha = res.alpha + v.alpha
                res.beta = res.beta + v.beta
            end
        end
        ACK.verifiers = res
    end
)

When(
    'verify the reflow signature credential',
    function()
        have 'reflow_signature'
        have 'verifiers'
        have 'reflow_seal'
        ZEN.assert(
            ABC.verify_cred_uid(
                ACK.verifiers,
                ACK.reflow_signature.proof,
                ACK.reflow_signature.zeta,
                ACK.reflow_seal.identity
            ),
            'Signature has an invalid credential to sign'
        )
    end
)

When(
    'check the reflow signature fingerprint is new',
    function()
        have 'reflow_signature'
        have 'reflow_seal'
        if not ACK.reflow_seal.fingerprints then
            return
        end
        ZEN.assert(
            not ACK.reflow_seal.fingerprints[ACK.reflow_signature.zeta],
            'Signature fingerprint is not new'
        )
    end
)

When(
    'add the reflow fingerprint to the reflow seal',
    function()
        have 'reflow_signature'
        have 'reflow_seal'
        if not ACK.reflow_seal.fingerprints then
            ACK.reflow_seal.fingerprints = {
                ACK.reflow_signature.zeta
            }
        else
            table.insert(
                ACK.reflow_seal.fingerprints,
                ACK.reflow_signature.zeta
            )
        end
    end
)

When(
    'add the reflow signature to the reflow seal',
    function()
        have 'reflow_seal'
        have 'reflow_signature'
        ACK.reflow_seal.SM =
            ACK.reflow_seal.SM + ACK.reflow_signature.signature
    end
)

When(
    'verify the reflow seal is valid',
    function()
        have 'reflow_seal'
        ZEN.assert(
            ECP2.miller(ACK.reflow_seal.verifier, ACK.reflow_seal.identity)
            ==
            ECP2.miller(G2, ACK.reflow_seal.SM),
            "reflow seal doesn't validates"
        )
    end
)

When(
    "aggregate the reflow seal array in ''",
    function(arr)
        have(arr)
        empty 'reflow seal'
        local dst = {}
        for _, v in pairs(ACK[arr]) do
            if not dst.UID then
                dst.UID = v.UID
            else
                dst.UID = dst.UID + v.UID
            end
            if not dst.SM then
                dst.SM = v.SM
            else
                dst.SM = dst.SM + v.SM
            end
            if not dst.verifier then
                dst.verifier = v.verifier
            else
                dst.verifier = dst.verifier + v.verifier
            end
        end
        ACK.reflow_seal = dst
    end
)

--------------------
-- MATERIAL PASSPORT
--
-- Simplified flow to generate and verify material passports, which
-- are a particular use-case of reflow signatures. Statements here do
-- implicit things and reduce complexity of operations, in particular
-- there is no multi-party computation in this process so credential
-- use is omitted.


-- aggregation supports single element arrays and fixes off-by-one
local function _aggregate_array(arr)
   assert(isarray(arr), "Cannot aggregate invalid array", 2)
   local res = arr[1]
   if #arr > 1 then
	  for i = 2, #arr do
		 res = res + arr[i]
	  end
   end
   return(res)
end

When(
   "create the material passport of ''",
   function(obj)
	  local key = havekey'reflow'
	  local cred = have'credentials'
	  local id = have'reflow identity'
	  have'issuer public key'
	  -- object to sign
	  local src = have(obj)
	  empty('material passport')
	  -- append agent id to track and trace
	  if not ACK.fingerprints then ACK.fingerprints = { } end
	  table.insert(ACK.fingerprints, id)
	  -- calculate object uid
	  local UID = _makeuid(src) -- reflow unique ID of object
	  -- calculate signing uid (aggregation of all fingerprints)
	  local SID = UID + _aggregate_array(ACK.fingerprints)
	  local r = INT.random() -- blinding factor
	  local p, z = ABC.prove_cred_uid(ACK.issuer_public_key,
									  ACK.credentials, ACK.keys.credential, SID)
	  ACK.material_passport = {
		 seal = {
			identity = UID,
			fingerprints = ACK.fingerprints,
			SM = (SID * r) + (SID * key), -- blinding factor
			verifier = (G2 * r) + (G2 * key)
		 },
		 proof = p,
		 zeta = z
	  }
end)

When(
   "verify the material passport of ''",
   function(obj)
	  local src = have(obj)
	  local mp = have'material passport'
	  local pub = have'issuer public key'
	  ZEN.assert(mp.seal.fingerprints,
				 "No fingerprints found in material passport seal: "..obj)
	  local UID = _makeuid(src)
	  ZEN.assert(UID == mp.seal.identity,
				 "Object does not match material passport identity (needs track and trace?): "..obj)
	  local SID = UID + _aggregate_array(mp.seal.fingerprints)
	  ZEN.assert(
		 ECP2.miller(mp.seal.verifier, SID)
		 ==
		 ECP2.miller(G2, mp.seal.SM),
		 "Object matches, but seal is invalid: "..obj)
	  ZEN.assert(
		 ABC.verify_cred_uid(ACK.issuer_public_key, mp.proof, mp.zeta, SID),
		 "Object and seal are valid, but proof of issuance fails: "..obj)
end)

-- Complex check calculates UID of object and compares to seal, if
-- correct then validates, else searches for .track array of seals and
-- calculates aggregated UID, if correct then validates
When(
   "verify the material passport of '' is valid",
   function(obj)
	  have(obj)
	  have(obj..'.seal')
end)
