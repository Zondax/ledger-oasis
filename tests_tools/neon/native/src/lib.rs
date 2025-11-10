use neon::prelude::*;
use neon::types::buffer::TypedArray;
use schnorrkel::{context::*, PublicKey, Signature};
use sha2::{Sha512_256 as Sha512Trunc256, digest::Digest};

fn schnorrkel_verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    // Get all arguments first
    let handler_pubkey = cx.argument::<JsBuffer>(0)?;
    let handler_context = cx.argument::<JsBuffer>(1)?;
    let handler_message = cx.argument::<JsBuffer>(2)?;
    let handler_signature = cx.argument::<JsBuffer>(3)?;

    // Then extract the slices
    let pubkeybytes = handler_pubkey.as_slice(&cx);
    let context = handler_context.as_slice(&cx);
    let message = handler_message.as_slice(&cx);
    let signaturebytes = handler_signature.as_slice(&cx);

    let pubkey = PublicKey::from_bytes(pubkeybytes);
    if !pubkey.is_ok(){
        return Ok(cx.boolean(false));
    }

    let pk = pubkey.unwrap();

    let signature = Signature::from_bytes(signaturebytes);
    if !signature.is_ok(){
        return Ok(cx.boolean(false));
    }

    let sig = signature.unwrap();

    let sigcontext = signing_context(context);

    let mut hasher = Sha512Trunc256::new();
    hasher.update(message);

    let v = pk.verify(sigcontext.hash256(hasher), &sig);
    if v.is_ok(){
        Ok(cx.boolean(true))
    }else{
        Ok(cx.boolean(false))
    }
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("schnorrkel_verify", schnorrkel_verify)?;
    Ok(())
}