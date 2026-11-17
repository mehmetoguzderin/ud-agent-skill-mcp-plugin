/** Finite comparison-block forecasts use only observed inert timing. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { buildStudyRows, STUDY_POLICY } from '../../evals/local/study.mjs';
import { forecastStudyBlock } from '../../evals/local/study-execution.mjs';
const manifest={rows:buildStudyRows(),policy:STUDY_POLICY};
function fixture(){return{active_model:'minicpm',active_row:null,deadline:28_800_000,models:{minicpm:{deadline:8_700_000}},rows:{},charged:{inference_requests:0,generated_tokens:0}};}
test('first seven-probe block reserves complete conservative comparisons and mode-reset overhead',()=>{
 const state=fixture(),before=JSON.stringify(state),row=manifest.rows[0];
 const forecast=forecastStudyBlock({manifest,state,row,now:0});assert.equal(forecast.remaining_peer_rows,7);assert.equal(forecast.per_unit_estimate_ms,95000);assert.equal(forecast.required_to_start_ms,7*95000+30000);assert.equal(forecast.allowed,true);
 state.models.minicpm.deadline=694999;assert.equal(forecastStudyBlock({manifest,state,row,now:0}).allowed,false);state.models.minicpm.deadline=8700000;assert.equal(JSON.stringify(state),before);
});
test('measured throughput uses the slowest comparable observation and never selects another task',()=>{
 const state=fixture();for(const row of manifest.rows.slice(0,7))state.rows[row.id]={status:'recorded',claimed_at:0,recorded_at:12000};
 state.rows[manifest.rows[1].id].recorded_at=21000;
 const forecast=forecastStudyBlock({manifest,state,row:manifest.rows[7],now:100000});assert.equal(forecast.per_unit_estimate_ms,21000);assert.equal(forecast.required_to_start_ms,7*21000);assert.equal(forecast.mode_switch_reserve_ms,0);
 assert.equal(forecastStudyBlock({manifest,state,row:manifest.rows[8],now:100000}).allowed,false);
});
test('resume preserves original deadlines and charges while marking partially forecastable blocks honestly',()=>{
 const state=fixture(),row=manifest.rows[0];state.rows[row.id]={status:'recorded',claimed_at:0,recorded_at:95000};state.charged.inference_requests=1;state.charged.generated_tokens=512;
 state.models.minicpm.deadline=200000;const before=JSON.stringify(state),next=manifest.rows[1],forecast=forecastStudyBlock({manifest,state,row:next,now:100000});
 assert.equal(forecast.allowed,true);assert.equal(forecast.comparison_block_started,true);assert.equal(forecast.remaining_peer_rows,6);assert.equal(forecast.can_finish_remaining_peers,false);assert.equal(forecast.required_to_start_ms,95000);assert.equal(forecast.deadline,200000);assert.equal(JSON.stringify(state),before);
 assert.equal(forecastStudyBlock({manifest,state,row:next,now:105001}).allowed,false);state.active_row=next.id;assert.equal(forecastStudyBlock({manifest,state,row:next,now:100000}).allowed,false);
});
